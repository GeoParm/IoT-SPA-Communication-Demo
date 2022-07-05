#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#include "serverutils.h"


void ufw_allow_ip_port(char *device_ip, short int port, int mode, int delay)
{
        /* This function creates a ufw command for the given IP and port.
         * If mode == 0 then a rule is added.
         * If mode == 1 then a rule is deleted.
         *
         * If delay is other than zero, then the command is executed with a
         * delay. The delay is implemented with `at` command (use
         * `apt-get install at` to use it. Also ensure atd service is running
         * by running `service atd start`).
         *
         * In order to use ufw commands, root access is required for the
         * gateway_controller execution.
         * */

        

        char port_str[10];
        // itoa(port, port_str, 10);

        char * command = (char *)malloc(100*sizeof(char));
        char * delay_str = (char *)malloc(100*sizeof(char));
        strcpy(command, "ufw ");
        if (mode == 1){
            strcat(command, "delete ");}
        strcat(command, "allow from ");
        strcat(command, device_ip);
        strcat(command, " to any port");

        // strcat(command, port_str);
        sprintf(command, "%s %hd", command, port);
        if (delay > 0){
            sprintf(delay_str, "echo '%s'|at now + %d min", command, delay);
            strcpy(command, delay_str);
            }
        printf("%s\n", command);
        printf("\n");
        system(command);
        free(command);
        free(delay_str);

}


int device_authentication(char * device_id, unsigned char * key) {

    /*
    Performs device authentication. Tries to connect to a local sqlite DB. 
    If connection is succesful, a query is executed with the device_id, to obtain 
    the encryption-decryption key for the particular device. If the key retrieval is 
    succeful, return 0, else return 1.
    */
    sqlite3 *db;
    char *err_msg = 0;
    int i,j;
    rows_counter = 0;
    int rc = sqlite3_open(AUTH_DB, &db);

    if (rc != SQLITE_OK) {

        fprintf(stderr, "Cannot open database: %s\n",
                sqlite3_errmsg(db));
        sqlite3_close(db);

        return 1;
    }

    // initialize array to store the key that is retrieved from sqlite.
    unsigned char *key_in_db =  (unsigned char *)malloc(KEY_LEN * sizeof(unsigned char));

    // Create the query
    char * sql = (char *)malloc(100*sizeof(char));
    sprintf(sql, "SELECT key FROM AUTH_DEVICES WHERE device_id == '%s';", device_id);

    rc = sqlite3_exec(db, sql, callback, key_in_db, &err_msg);

    if (rc != SQLITE_OK ) {

        printf("Failed to select data\n");
        printf("SQL error: %s\n", err_msg);

        sqlite3_free(err_msg);
        sqlite3_close(db);

        return 1;
    }
    printf("KEYS FOUND: %d\n", rows_counter);
    // Copy the key result from the query, to the return variable `key`.
    memcpy(key, key_in_db, KEY_LEN*sizeof(unsigned char));

    /* Print the key */
    for (int j = 0; j < KEY_LEN; j++)
        {
                printf("%02X ", key[j]);
        }
    printf("\n");

    sqlite3_close(db);

    return 0;
}

int callback(void *NotUsed, int argc, char **argv,
                    char **azColName) {

    unsigned char *key_in_db = (unsigned char *)NotUsed;

    for (int i = 0; i < argc; i++) {  // i is columns counter

        printf("%d: %s = ", rows_counter, azColName[i]);
        for (int j = 0; j < 16; j++)
            {
                    printf("%02X ", (unsigned char)argv[i][j]);
            }
        printf("\n");
        memcpy(key_in_db,  argv[i], KEY_LEN*sizeof(char));
        rows_counter++;
    }

    printf("\n");

    return 0;
}
