/*
 * connect.c
 */

#include "connect.h"
#include <php.h>

void uniauth_storage_delete(struct uniauth_storage* stor)
{
    /* Free the members. Some members may not be allocated. The structure itself
     * is not free'd here (since it may be allocated on the stack).
     */

    if (stor->key != NULL) {
        efree(stor->key);
    }
    if (stor->username != NULL) {
        efree(stor->username);
    }
    if (stor->displayName != NULL) {
        efree(stor->displayName);
    }
    if (stor->redirect != NULL) {
        efree(stor->redirect);
    }
}
