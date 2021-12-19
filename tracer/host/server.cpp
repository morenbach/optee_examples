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

#define TRACE(msg)            cout << msg
#define TRACE_ACTION(a, k, v) cout << a << " (" << k << ", " << v << ")\n"

// map<utility::string_t, utility::string_t> dictionary;

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

void display_json(
   json::value const & jvalue,
   utility::string_t const & prefix)
{
   cout << prefix << jvalue.serialize() << endl;
}


void handle_request(
   http_request request,
   function<void(json::value const &, json::value &)> action)
{
   auto answer = json::value::object();

   request
      .extract_json()
      .then([&answer, &action](pplx::task<json::value> task) {
         try
         {
            auto const & jvalue = task.get();
            // display_json(jvalue, "R: ");

            if (!jvalue.is_null())
            {
               action(jvalue, answer);
            }
         }
         catch (http_exception const & e)
         {
            cout << e.what() << endl;
         }
      })
      .wait();

   
   // display_json(answer, "S: ");

   request.reply(status_codes::OK, answer);
}


// void handle_put(http_request request)
// {
//    TRACE("\nhandle PUT\n");

//    handle_request(
//       request,
//       [](json::value const & jvalue, json::value & answer)
//    {
//       for (auto const & e : jvalue.as_object())
//       {
//          if (e.second.is_string())
//          {
//             auto key = e.first;
//             auto value = e.second.as_string();

//             if (dictionary.find(key) == dictionary.end())
//             {
//                TRACE_ACTION("added", key, value);
//                answer[key] = json::value::string("<put>");
//             }
//             else
//             {
//                TRACE_ACTION("updated", key, value);
//                answer[key] = json::value::string("<updated>");
//             }

//             dictionary[key] = value;
//          }
//       }
//    });
// }

// void handle_del(http_request request)
// {
//    TRACE("\nhandle DEL\n");

//    handle_request(
//       request,
//       [](json::value const & jvalue, json::value & answer)
//    {
//       set<utility::string_t> keys;
//       for (auto const & e : jvalue.as_array())
//       {
//          if (e.is_string())
//          {
//             auto key = e.as_string();

//             auto pos = dictionary.find(key);
//             if (pos == dictionary.end())
//             {
//                answer[key] = json::value::string("<failed>");
//             }
//             else
//             {
//                TRACE_ACTION("deleted", pos->first, pos->second);
//                answer[key] = json::value::string("<deleted>");
//                keys.insert(key);
//             }
//          }
//       }

//       for (auto const & key : keys)
//          dictionary.erase(key);
//    });
// }



void handle_post(http_request request)
{
   TRACE("\nhandle POST\n");

   handle_request(
      request,
      [](json::value const & jvalue, json::value & answer)
   {
      string attestation_type;
      string attestation_value;
      string nonce;

      for (auto const & e : jvalue.as_object())
      {
         if (!e.second.is_string()) { // unexpected request format
            return;
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
            return;
         }
      }

      cout << "GOT REQUEST: " << attestation_type << ", " << attestation_value << ", " << nonce << endl;

      size_t bufsiz = 10*1024*1024; // 10MB
      char* buf = (char*)malloc(bufsiz);
      if (!buf) { // failed to allocate enough memory for trace result
         return;
      }

      if (attestation_type == "cfa") {
         // prep buffer in normal world that will store the call stack
         //
         int pid = getProcIdByName(attestation_value);      
         if (pid == -1) {
            // invalid attestation value recieved, ignore request
            return;
         }

         do_backtrace(pid);

         // trace_cfa(buf, bufsiz);
      } else if (attestation_type == "civ") {
         trace_civ(buf, bufsiz);
      } else {
         // unsupported attestation type - ignore request
         return;
      }

      // Return the response trace in the answer.
      //
      answer["trace"] = 0;// buf;
   });
}

// void handle_get(http_request request)
// {
//       handle_request(
//       request,
//       [](json::value const & jvalue, json::value & answer)
//    {
//       for (auto const & e : jvalue.as_array())
//       {
//          if (e.is_string())
//          {
//             auto key = e.as_string();
//             cout << "GOT request: " << key << endl;

//             answer[key] = json::value::string("<nil>");
//          }
//       }
//    });
// }


extern "C" int start_server()
{
   http_listener listener("http://localhost:6502/tracer");

   // listener.support(methods::GET,  handle_get);
   listener.support(methods::POST, handle_post);
   // listener.support(methods::PUT,  handle_put);
   // listener.support(methods::DEL,  handle_del);

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

