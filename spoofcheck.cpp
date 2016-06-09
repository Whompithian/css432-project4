/*
 * @file    spoofcheck.cpp
 * @brief   This program listens on a specified TCP port for a connection. When
 *           a client connects, the program retrieves that client's DNS records
 *           and checks to make sure they match the information reported in the
 *           TCP packet headers. It prints out the information reported by the
 *           client and the information gathered from the registry. If they
 *           match, it declares the client to be honest. Otherwise, it declares
 *           the client an imposter.
 * @author  Brendan Sweeney, SID 1161836
 * @date    November 15, 2012
 */

#include <cstdlib>
#include "Socket.h"

using namespace std;


const int ON = 1;                   // for asynchronous connection switch
const int ACCEPT = 5;               // number of clients to allow in queue


int main(int argc, char** argv) {
    int    counter;                         // counter for loops and things
    int    hostPort;                        // a server port number
    int    serverSd;                        // listen socket
    int    clientSd;                        // accept socket
    struct sockaddr_in acceptSockAddr;      // address of listen socket
    struct sockaddr_in clientAddr;          // address of data socket
    socklen_t addrSize = sizeof(clientAddr);
    struct hostent *clientEnt   = NULL;     // client host entry information
    struct in_addr  tempAddr;               // for addresses in hostent
    char           *clientIp    = NULL;     // client dotted decimal IP address
    char           *currentIp   = NULL;     // known dotted decimal IP address
    uint16_t        clientPort;             // client connection port
    in_addr_t       clientLoc;              // client machine address
    bool            trusted     = false;    // whether we yet trust the client
    
    // check argument count
    if (argc != 2) {
        cerr << "usage: " << argv[0] << " PORT" << endl;
        exit(EXIT_FAILURE);
    } // end if (argc != 2)
    
    // read a port from argument list
    hostPort = atoi(argv[1]);
    if (hostPort < 1024 || hostPort > 65535)
    {
        cerr << argv[0] << ": port must be between 1024 and 65535" << endl;
        exit(EXIT_FAILURE);
    } // end if (port < 1024 || port > 65535)
    
    // prepare the socket
    acceptSockAddr.sin_family      = AF_INET;   // Address Family Internet
    acceptSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    acceptSockAddr.sin_port        = htons(hostPort);
    
    // active open, ensure success before continuing
    if ((serverSd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        cerr << argv[0] << ": socket failure" << endl;
        exit(EXIT_FAILURE);
    } // end if ((serverSd = socket(...)))
    
    // setup server socket, bind, and listen for client connection
    setsockopt(serverSd, SOL_SOCKET, SO_REUSEADDR, (char*)&ON, sizeof(int));
    bind(serverSd, (sockaddr*)&acceptSockAddr, sizeof(acceptSockAddr));
    listen(serverSd, ACCEPT);
    
    // sleep indefinitely
    while(true) {
        // establish client connection
        clientSd = accept(serverSd, (sockaddr*)&clientAddr, &addrSize);
        
        // let a child process the connection
        if (fork() == 0) {
            getpeername(clientSd, (sockaddr*)&clientAddr, &addrSize);
            
            // obtain client information
            clientIp   = inet_ntoa(clientAddr.sin_addr);
            clientPort = ntohs(clientAddr.sin_port);
            clientLoc  = inet_addr(clientIp);
            clientEnt  = gethostbyaddr(&clientLoc,
                                        sizeof(unsigned int), AF_INET);
            
            // print known client information
            cout << "\nClient address = " << clientIp
                 << " port = " << clientPort << endl;

            if (clientEnt != NULL) {
                cout << "Official hostname: " << clientEnt->h_name << endl;
                cout << "Aliases: " << endl;
                counter = 0;

                // check for aliases
                if (clientEnt->h_aliases[counter] == NULL) {
                    cout << "    none" << endl;
                } // end if (clientEnt->h_aliases[counter] == NULL)
                else {
                    while(clientEnt->h_aliases[counter] != NULL) {
                        cout << "    "
                             << clientEnt->h_aliases[counter++] << endl;
                    } // end while(clientEnt->h_aliases[counter++] != NULL)
                } // end else (clientEnt->h_aliases[counter] != NULL)

                cout << "IP addresses: " << endl;
                counter = 0;

                // check for IP addresses
                if (clientEnt->h_addr_list[counter] == NULL) {
                    cout << "    none" << endl;
                } // end if (clientEnt->h_addr_list[counter] == NULL)
                else {
                    while(clientEnt->h_addr_list[counter] != NULL) {
                        tempAddr.s_addr =
                                       *(u_long*)clientEnt->h_addr_list[counter++];
                        currentIp = inet_ntoa(tempAddr);
                        cout << "    " << currentIp;

                        // check client validity
                        if (strcmp(clientIp, currentIp) == 0) {
                            cout << " ... hit!";
                            trusted = true;
                        } // end if (strcmp(clientIp, currentIp) == 0)

                        cout << endl;
                    } // end while(clientEnt->h_addr_list[counter++] != NULL)
                } // end else (clientEnt->h_addr_list[counter] != NULL)
            } // end if (clientEnt != NULL)
            
            if (trusted) {
                cout << "An honest client" << endl;
            } // end if (trusted)
            else {
                cout << "Imposter!" << endl;
            } // end else (!trusted)
            
            // cleanup and pointer dedanglification
            close(clientSd);
            clientEnt   = NULL;
            clientIp    = NULL;
            currentIp   = NULL;
            exit(EXIT_SUCCESS);
        } // end if (fork() == 0)
        
        close(clientSd);
    } // end while(true)
    
    close(serverSd);
    return 0;
} // end main(int, char**)
