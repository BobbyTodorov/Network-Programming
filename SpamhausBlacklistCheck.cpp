#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

unsigned short ExtractLastOctet(in_addr ip)
{
    char* buffer = inet_ntoa(ip);
    unsigned short i = 0;
    unsigned short numberOfDots = 0;
    char temp;
    char lastOctet[3];
    while (true)
    {
        
        temp = buffer[++i];
        if (temp == '.')
            numberOfDots++;
        if (numberOfDots == 3)
        {
            unsigned short j = 0;
            i++;
            while (temp != '\0')
            {
                temp = buffer[i++];
                lastOctet[j++] = temp;
            }
            return (unsigned short)atoi(lastOctet);
        }
    }
}

void PrintIPCodeInfo(in_addr ip)
{
    std::cout << "'" << inet_ntoa(ip);
    switch (ExtractLastOctet(ip))
    {
    case 2:
        std::cout << " - SBL - Spamhaus SBL Data'";
        break;
    case 3:
        std::cout << " - SBL - Spamhaus SBL CSS Data'";
        break;
    case 4:
        std::cout << " - XBL - CBL Data'";
        break;
    case 9:
        std::cout << " - SBL - Spamhaus DROP/EDROP Data'";
        break;
    case 10:
        std::cout << " - PBL - ISP Maintained'";
        break;
    case 11:
        std::cout << " - PBL - Spamhaus Maintained'";
        break;
    }
    std::cout << std::endl;
}

std::string ReverseIPString(std::string ip)
{
    std::string octet1, octet2, octet3, octet4;
    unsigned short numbOfDots = 0;
    for (unsigned short i = 0; i < ip.length(); ++i)
    {
        if (ip[i] == '.')
        {
            numbOfDots++;
            continue;
        }
        switch (numbOfDots)
        {
        case 0:
            octet1 += ip[i];
            break;
        case 1:
            octet2 += ip[i];
            break;
        case 2:
            octet3 += ip[i];
            break;
        case 3:
            octet4 += ip[i];
            break;
        }
    }
    return (octet4 + "." + octet3 + "." + octet2 + "." + octet1);
}

int main()
{
    // Initialize Winsock
    WSADATA wsaData;
    int iResult;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) 
    {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }
    
    // Get IPs from cmd
    unsigned numbOfIPs;
    std::cin >> numbOfIPs;

    std::string* IPs = new std::string[numbOfIPs];

    for (unsigned i = 0; i < numbOfIPs; ++i)
        std::cin >> IPs[i];

    // Check each IP's returned code and print result
    struct hostent* remoteHost;
    std::string hostName;
    struct in_addr addr;

    for (unsigned i = 0; i < numbOfIPs; ++i)
    {
        std::string reversedIP = ReverseIPString(IPs[i]);
        
        hostName = reversedIP + ".zen.spamhaus.org";
        remoteHost = gethostbyname(hostName.c_str());

        std::cout << std::endl;
        if (remoteHost == NULL) 
            std::cout << "The IP address: " << IPs[i] << " is NOT found in the Spamhaus blacklists." << std::endl;
        else 
        {
            unsigned int i = 0;
            std::cout << "The IP address: " << IPs[i] << " is found in the following Spamhaus public IP zone:" << std::endl;
            while (remoteHost->h_addr_list[i] != 0)
            {
                addr.s_addr = *(u_long*)remoteHost->h_addr_list[i++];
                PrintIPCodeInfo(addr);
            }
        }
    }

    system("Pause");
    return 0;
}

