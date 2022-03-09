#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#pragma comment(lib, "cpprest_2_10")

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;

#include <iostream>
#include <map>
#include <set>
#include <string>

#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <vector>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>

#include "backtrace.h"
#include "tracer_interface.h"

using namespace std;

extern pthread_mutex_t cfa_mutex; // = PTHREAD_MUTEX_INITIALIZER;


#define TRACE(msg)            cout << msg
#define TRACE_ACTION(a, k, v) cout << a << " (" << k << ", " << v << ")\n"

int getProcIdByName(string procName)
{
    int pid = -1;

    // Open the /proc directory
    DIR *dp = opendir("/proc");
    if (dp != NULL)
    {
        // Enumerate all entries in directory until process found
        struct dirent *dirp;
        while (pid < 0 && (dirp = readdir(dp)))
        {
            // Skip non-numeric entries
            int id = atoi(dirp->d_name);
            if (id > 0)
            {
                // Read contents of virtual /proc/{pid}/cmdline file
                string cmdPath = string("/proc/") + dirp->d_name + "/cmdline";
                ifstream cmdFile(cmdPath.c_str());
                string cmdLine;
                getline(cmdFile, cmdLine);
                if (!cmdLine.empty())
                {
                    // Keep first cmdline item which contains the program path
                    size_t pos = cmdLine.find('\0');
                    if (pos != string::npos)
                        cmdLine = cmdLine.substr(0, pos);
                    // Keep program name only, removing the path
                    pos = cmdLine.rfind('/');
                    if (pos != string::npos)
                        cmdLine = cmdLine.substr(pos + 1);
                    // Compare against requested process name
                    if (procName == cmdLine)
                        pid = id;
                }
            }
        }
    }

    closedir(dp);

    return pid;
}

// void display_json(
//    json::value const & jvalue,
//    utility::string_t const & prefix)
// {
//    cout << prefix << jvalue.serialize() << endl;
// }

void handle_request(
   http_request request,
   function<char*(json::value const &)> action)
{
   char* answer; // = json::value::object();

   request
      .extract_json()
      .then([&answer, &action](pplx::task<json::value> task) {
         try
         {
            auto const & jvalue = task.get();

            if (!jvalue.is_null())
            {
               answer = action(jvalue);
            }
         }
         catch (http_exception const & e)
         {
            cout << e.what() << endl;
         }
      })
      .wait();

   
   request.reply(status_codes::OK, json::value(answer));
}

char* g_response_buf;
#define RESPONSE_SIZE (1 << 20) // 1MB

void handle_post(http_request request)
{
   // TRACE("\nhandle POST\n");

   handle_request(
      request,
      [](json::value const & jvalue)
   {
      char* res = NULL;
      string attestation_type;
      string attestation_value;
      string nonce;

      for (auto const & e : jvalue.as_object())
      {
         if (!e.second.is_string()) { // unexpected request format
            return res;
         }

         auto key = e.first;
         auto value = e.second.as_string();

         // cout << "==V: " << key << " : " << value << endl;

         if (key == "attestation_type") {
            attestation_type = value;
         } else if (key == "attestation_value") {
            attestation_value = value;
         } else if (key == "nonce") {
            nonce = value;
         } else {
            // unexpected request format
            return res;
         }
      }

      // cout << "GOT REQUEST: " << attestation_type << ", " << attestation_value << ", " << nonce << endl;

      if (attestation_type == "cfa") {    
         // cout << "IN CFA LOGIC!" << endl;     
         pthread_mutex_lock( &cfa_mutex );         
         trace_cfa(0,NULL,0, g_response_buf, RESPONSE_SIZE);         
         pthread_mutex_unlock( &cfa_mutex );
         // cout << "Got CFA response" << endl;
         res = g_response_buf;
         return res;

         // prep buffer in normal world that will store the call stack
         //
         int pid = getProcIdByName(attestation_value);      
         if (pid == -1) {
            // invalid attestation value recieved, ignore request
            return res;
         }

         do_backtrace(pid, g_response_buf, RESPONSE_SIZE);

         // trace_cfa(buf, bufsiz);
      } else if (attestation_type == "civ") {
         trace_civ(g_response_buf, RESPONSE_SIZE);
      } else {
         // unsupported attestation type - ignore request
         return res;
      }

      // Return the response trace in the answer.
      //
      // answer["trace"] = 0;// buf;
      res = g_response_buf;
      return res;
   });
}

extern "C" int start_rest_server()
{
   http_listener listener("http://localhost:6502/tracer");

   listener.support(methods::POST, handle_post);

   g_response_buf = (char*)malloc(RESPONSE_SIZE);
   if (!g_response_buf) { 
      // Failed to allocate enough memory for trace result
      //
      TRACE("Failed allocating response buffer\n");
      return -1;
   }

   try
   {
      listener
         .open()
         .then([&listener]() {TRACE("REST server listening to trace requests\n"); })
         .wait();

      while (true);
   }
   catch (exception const & e)
   {
      cout << e.what() << endl;
   }

   return 0;
}

