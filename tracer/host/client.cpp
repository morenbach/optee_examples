#include <cpprest/http_client.h>
#include <cpprest/json.h>
#pragma comment(lib, "cpprest_2_10")

using namespace web;
using namespace web::http;
using namespace web::http::client;

#include <iostream>
using namespace std;

void display_json(
   json::value const & jvalue, 
   utility::string_t const & prefix)
{
    // cout << "HELLO" << endl;
   cout << prefix << jvalue.serialize() << endl;
}

pplx::task<http_response> make_task_request(
   http_client & client,
   method mtd,
   json::value const & jvalue)
{
   return (mtd == methods::GET || mtd == methods::HEAD) ?
      client.request(mtd, U("/restdemo")) :
      client.request(mtd, U("/restdemo"), jvalue);
}

void make_request(
   http_client & client, 
   method mtd, 
   json::value const & jvalue)
{
   make_task_request(client, mtd, jvalue)
      .then([](http_response response)
      {
         if (response.status_code() == status_codes::OK)
         {
            return response.extract_json();
         }
         return pplx::task_from_result(json::value());
      })
      .then([](pplx::task<json::value> previousTask)
      {
         try
         {
            display_json(previousTask.get(), U("R: "));
         }
         catch (http_exception const & e)
         {
            wcout << e.what() << endl;
         }
      })
      .wait();
}

int main()
{
   http_client client(U("http://localhost:6502/tracer"));

   wcout << U("\nPOST (v)\n");
   auto putvalue = json::value::object();
   putvalue[U("attestation_type")] = json::value::string(U("cfa"));
   putvalue[U("attestation_value")] = json::value::string(U("procname"));
   putvalue[U("nonce")] = json::value::string(U("0xfefefefefefefefe"));

   make_request(client, methods::POST, putvalue);
/*
   auto putvalue = json::value::object();
   putvalue[U("one")] = json::value::string(U("100"));
   putvalue[U("two")] = json::value::string(U("200"));

   wcout << U("\nPUT (add values)\n");
   display_json(putvalue, U("S: "));
   make_request(client, methods::PUT, putvalue);

   auto getvalue = json::value::array();
   getvalue[0] = json::value::string(U("one"));
   getvalue[1] = json::value::string(U("two"));
   getvalue[2] = json::value::string(U("three"));

   wcout << U("\nPOST (get some values)\n");
   display_json(getvalue, U("S: "));
   make_request(client, methods::POST, getvalue);

   auto delvalue = json::value::array();
   delvalue[0] = json::value::string(U("one"));

   wcout << U("\nDELETE (delete values)\n");
   display_json(delvalue, U("S: "));
   make_request(client, methods::DEL, delvalue);

   wcout << U("\nPOST (get some values)\n");
   display_json(getvalue, U("S: "));
   make_request(client, methods::POST, getvalue);

   auto nullvalue = json::value::null();

   wcout << U("\nGET (get all values)\n");
   display_json(nullvalue, U("S: "));
   make_request(client, methods::GET, nullvalue);
*/
   return 0;
}
