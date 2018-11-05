#ifndef _GSWUI_EVENT_CONSTANTS_LOG_
#define _GSWUI_EVENT_CONSTANTS_LOG_
//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: QUERY_AUTHORIZATION_OBJECT_ERROR
//
// MessageText:
//
//  Query authorization object error.
//
#define QUERY_AUTHORIZATION_OBJECT_ERROR 0xC0000001L

//
// MessageId: OPEN_AUTHORIZATION_OBJECT_ERROR
//
// MessageText:
//
//  Open authorization object error.
//
#define OPEN_AUTHORIZATION_OBJECT_ERROR  0xC0000002L

//
// MessageId: REGISTER_CLIENT_ERROR
//
// MessageText:
//
//  Register client error.
//
#define REGISTER_CLIENT_ERROR            0xC0000003L

//
// MessageId: PUT_REPLY_ERROR
//
// MessageText:
//
//  Put reply error.
//
#define PUT_REPLY_ERROR                  0xC0000004L

//
// MessageId: WAIT_START_SERVICE_ERROR
//
// MessageText:
//
//  Wait start service error.
//
#define WAIT_START_SERVICE_ERROR         0xC0000005L

#endif /* _GSWUI_EVENT_CONSTANTS_LOG_ */