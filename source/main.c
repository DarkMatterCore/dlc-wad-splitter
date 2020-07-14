/*
 * main.c
 *
 * Copyright (c) 2020, DarkMatterCore <pabloacurielz@gmail.com>.
 *
 * This file is part of dlc-wad-splitter (https://github.com/DarkMatterCore/dlc-wad-splitter).
 *
 * dlc-wad-splitter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dlc-wad-splitter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils.h"
#include "wad.h"

#define PATH_COUNT  2

int main(int argc, char **argv)
{
    int ret = 0;
    
    /* Reserve memory for an extra temporary path. */
    os_char_t *paths[PATH_COUNT + 1] = {0};
    
    CertificateChain *cert_chain = NULL;
    
    Ticket *ticket = NULL;
    
    TitleMetadata *tmd = NULL;
    TmdCommonBlock *tmd_common_block = NULL;
    
    u16 dlc_content_count = 0, tmd_content_count = 0;
    
    printf("\ndlc-wad-splitter v%s (c) DarkMatterCore.\n", VERSION);
    printf("Built: %s %s.\n\n", __TIME__, __DATE__);
    
    if (argc != (PATH_COUNT + 2) || strlen(argv[1]) >= MAX_PATH || (strlen(argv[2]) + SPLIT_WAD_MAX_NAME_LENGTH) >= MAX_PATH || \
        (dlc_content_count = (u16)strtoul(argv[3], NULL, 10)) >= (TMD_MAX_CONTENT_COUNT - 1) || errno == ERANGE)
    {
        printf("Usage: %s <input WAD> <output dir> <content count per split DLC>\n\n", argv[0]);
        printf("Paths must not exceed %u characters. Relative paths are supported.\n", MAX_PATH - 1);
        printf("The input WAD package must hold a TMD with a valid signature, as well as all the contents referenced\n");
        printf("in the content records section from the TMD. If a single content is missing or has a wrong hash, the\n");
        printf("process will be stopped.\n");
        printf("Furthermore, the total content count minus 1 must be a multiple of the provided content count.\n");
        printf("Output split DLC WADs will hold content #0 + \"content count\" contents.\n");
        printf("For more information, please visit: https://github.com/DarkMatterCore/dlc-wad-splitter.\n\n");
        ret = -1;
        goto out;
    }
    
    /* Allocate memory for the certificate chain, ticket and TMD. */
    cert_chain = (CertificateChain*)calloc(1, sizeof(CertificateChain));
    ticket = (Ticket*)calloc(1, sizeof(Ticket));
    tmd = (TitleMetadata*)calloc(1, sizeof(TitleMetadata));
    if (!cert_chain || !ticket || !tmd)
    {
        ERROR_MSG("Error allocating memory for certificate chain / ticket / TMD structs!");
        ret = -2;
        goto out;
    }
    
    /* Generate path buffers. */
    for(u32 i = 0; i <= PATH_COUNT; i++)
    {
        /* Allocate memory for the current path. */
        paths[i] = (os_char_t*)calloc(MAX_PATH, sizeof(os_char_t));
        if (!paths[i])
        {
            ERROR_MSG("Error allocating memory for path #%u!", i);
            ret = -3;
            goto out;
        }
        
        if (i == PATH_COUNT)
        {
            /* Save temporary path and create it. */
            os_snprintf(paths[i], MAX_PATH, "." OS_PATH_SEPARATOR "dlc-wad-splitter_wad_data");
            os_mkdir(paths[i], 0777);
        } else {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
            /* Convert current path string to UTF-16. */
            /* We'll only need to perform manual conversion at this point. */
            if (!utilsConvertUTF8ToUTF16(paths[i], argv[i + 1]))
            {
                ERROR_MSG("Failed to convert path from UTF-8 to UTF-16!");
                ret = -4;
                goto out;
            }
#else
            /* Copy path. */
            os_snprintf(paths[i], MAX_PATH, "%s", argv[i + 1]);
#endif
            
            /* Check if the output directory string ends with a path separator. */
            /* If so, remove it. */
            if (i == (PATH_COUNT - 1))
            {
                u64 path_len = strlen(argv[i + 1]);
                if (argv[i + 1][path_len - 1] == *((u8*)OS_PATH_SEPARATOR)) paths[i][path_len - 1] = (os_char_t)0;
                os_mkdir(paths[i], 0777);
            }
        }
    }
    
    /* Unpack input WAD package. */
    if (!wadUnpackInstallablePackage(paths[0], paths[2], cert_chain, ticket, tmd))
    {
        ret = -5;
        goto out;
    }
    
    printf("WAD package \"" OS_PRINT_STR "\" successfully unpacked.\n\n", paths[2]);
    
    /* Get TMD common block and retrieve the content count. */
    tmd_common_block = tmdGetCommonBlock(tmd->data);
    tmd_content_count = bswap_16(tmd_common_block->content_count);
    
    if (tmd_content_count <= 1 || dlc_content_count > (tmd_content_count - 1) || ((tmd_content_count - 1) % dlc_content_count) > 0)
    {
        ERROR_MSG("Invalid TMD content count and/or content count per split DLC! (%u contents available).", tmd_content_count);
        ret = -6;
        goto out;
    }
    
    /* Generate split DLC packages. */
    if (!wadGenerateSplitDlcPackages(paths[2], paths[1], cert_chain, ticket, tmd, dlc_content_count))
    {
        ret = -7;
        goto out;
    }
    
    printf("Process finished!\n\n");
    
out:
    if (ret < 0 && ret != -1) printf("Process failed!\n\n");
    
    if (tmd)
    {
        tmdFreeTitleMetadata(tmd);
        free(tmd);
    }
    
    if (ticket)
    {
        tikFreeTicket(ticket);
        free(ticket);
    }
    
    if (cert_chain)
    {
        certFreeCertificateChain(cert_chain);
        free(cert_chain);
    }
    
    /* Remove unpacked WAD directory. */
    if (paths[2]) utilsRemoveDirectoryRecursively(paths[2]);
    
    for(u32 i = 0; i <= PATH_COUNT; i++)
    {
        if (paths[i]) free(paths[i]);
    }
    
    return ret;
}
