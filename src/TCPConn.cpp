#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sstream>
#include "TCPConn.h"
#include "strfuncts.h"
#include <crypto++/secblock.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/rijndael.h>
#include <crypto++/gcm.h>
#include <crypto++/aes.h>
#include <random>

using namespace CryptoPP;

// Common defines for this TCPConn
const unsigned int iv_size = AES::BLOCKSIZE;
const unsigned int key_size = AES::DEFAULT_KEYLENGTH;
const unsigned int auth_size = 16;

/**********************************************************************************************
 * TCPConn (constructor) - creates the connector and initializes - creates the command strings
 *                         to wrap around network commands
 *
 *    Params: key - reference to the pre-loaded AES key
 *            verbosity - stdout verbosity - 3 = max
 *
 **********************************************************************************************/

TCPConn::TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity):
                                    _data_ready(false),
                                    _aes_key(key),
                                    _verbosity(verbosity),
                                    _server_log(server_log)
{
   // prep some tools to search for command sequences in data
   uint8_t slash = (uint8_t) '/';
   c_rep.push_back((uint8_t) '<');
   c_rep.push_back((uint8_t) 'R');
   c_rep.push_back((uint8_t) 'E');
   c_rep.push_back((uint8_t) 'P');
   c_rep.push_back((uint8_t) '>');

   c_endrep = c_rep;
   c_endrep.insert(c_endrep.begin()+1, 1, slash);

   c_ack.push_back((uint8_t) '<');
   c_ack.push_back((uint8_t) 'A');
   c_ack.push_back((uint8_t) 'C');
   c_ack.push_back((uint8_t) 'K');
   c_ack.push_back((uint8_t) '>');

   c_auth.push_back((uint8_t) '<');
   c_auth.push_back((uint8_t) 'A');
   c_auth.push_back((uint8_t) 'U');
   c_auth.push_back((uint8_t) 'T');
   c_auth.push_back((uint8_t) '>');

   c_endauth = c_auth;
   c_endauth.insert(c_endauth.begin()+1, 1, slash);

   c_sid.push_back((uint8_t) '<');
   c_sid.push_back((uint8_t) 'S');
   c_sid.push_back((uint8_t) 'I');
   c_sid.push_back((uint8_t) 'D');
   c_sid.push_back((uint8_t) '>');

   c_endsid = c_sid;
   c_endsid.insert(c_endsid.begin()+1, 1, slash);
}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   // Accept the connection
   bool results = _connfd.acceptFD(server);


   // Set the state as waiting for the authorization packet
   _status = s_connected;
   _connected = true;
   return results;
}

/**********************************************************************************************
 * sendData - sends the data in the parameter to the socket
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendData(std::vector<uint8_t> &buf) {
   
   _connfd.writeBytes<uint8_t>(buf);
   
   return true;
}

/**********************************************************************************************
 * sendEncryptedData - sends the data in the parameter to the socket after block encrypting it
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendEncryptedData(std::vector<uint8_t> &buf) {

   // Encrypt
   encryptData(buf);

   // And send!
   return sendData(buf);
}

/**********************************************************************************************
 * encryptData - block encrypts data and places the results in the buffer in <ID><Data> format
 *
 *    Params:  buf - where to place the <IV><Data> stream
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

void TCPConn::encryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);
   AutoSeededRandomPool rnd;

   // Generate our random init vector
   rnd.GenerateBlock(init_vector, init_vector.size());

   // Encrypt the data
   CFB_Mode<AES>::Encryption encryptor;
   encryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string cipher;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(encryptor, new StringSink(cipher)));

   // Now add the IV to the stream we will be sending out
   std::vector<uint8_t> enc_data(init_vector.begin(), init_vector.end());
   enc_data.insert(enc_data.end(), cipher.begin(), cipher.end());
   buf = enc_data;
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   try {
      switch (_status) {

         /** Client **/
         // Client: Just connected, send our SID
         // Default
         case s_connecting:
            sendSID();
            break;

          // Client: Wait for Rand Bytes string
          case c_waitForRBString:
              c_waitForRB();
              break;

          // Client: Wait for SID
          case c_waitForSID:
              c_waitSID();
              break;

          // Client: Wait for the encrypted bytes after sending random bytes for auth
          case c_waitForEBString:
              c_waitForEB();
              break;

          // Client: connecting user - replicate data
          // Default
          case s_datatx:
              transmitData();
              break;

          // Client: Wait for acknowledgement that data sent was received before disconnecting
          // Default
          case s_waitack:
              awaitAck();
              break;

          /** Server **/
          // Server: Wait for the SID from a newly-connected client, then send our authentication random bytes
          // Default -- To Do: Modify
          case s_connected:
              waitForSID();
              break;

         // Server: Wait for the encrypted bytes from the client
          case s_waitForEBString:
              s_waitForEB();
              break;

         // Server: Wait for the random byte string to be sent
          case s_waitForRBString:
              s_waitForRB();
              break;

         // Server: Receive data from the client
         // Default
         case s_datarx:
            waitForData();
            break;
         
         // Server: Data received and conn disconnected, but waiting for the data to be retrieved
         case s_hasdata:
            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.\n";
      disconnect();
      return;
   }

}

/**********************************************************************************************
 * sendSID()  - Client: after a connection, client sends its Server ID to the server
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::sendSID() {
//    std::cout << "\n\n----(1) Client: Sending SID----\n\n";
   std::vector<uint8_t> buf(_svr_id.begin(), _svr_id.end());
   wrapCmd(buf, c_sid, c_endsid);
   sendData(buf);

   _status = c_waitForRBString;
}

/**********************************************************************************************
 * waitForSID()  - receives the SID and sends our SID
 *
 * TO DO:
 * Modify to send random bytes, not SID
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForSID() {

   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
//       std::cout << "\n\n----(1) Server: Received SID from client; Sending random bytes----\n\n";
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "SID string from connecting client invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());

      // Send our Node ID
//      buf.assign(_svr_id.begin(), _svr_id.end());
//      wrapCmd(buf, c_sid, c_endsid);
//      sendData(buf);

        // Generate our random number
        this->genBytesForVerify();

        // Send our Random Byte number
        buf.assign(this->_gennedAuthStr.begin(), this->_gennedAuthStr.end());
        this->wrapCmd(buf, this->c_auth, this->c_endauth);
        sendData(buf);

       this->_status = s_waitForEBString;
//      _status = s_datarx;
   }
}


/**********************************************************************************************
 * transmitData()  - receives the SID from the server and transmits data
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn:: transmitData() {
   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
//       std::cout << "\n\n----(5) Client: Sending data----\n\n";
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "SID string from connected server invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());

      // Send the replication data
      sendData(_outputbuf);

      if (_verbosity >= 3)
         std::cout << "Successfully authenticated connection with " << getNodeID() <<
                      " and sending replication data.\n";

      // Wait for their response
      _status = s_waitack;
   }
}


/**********************************************************************************************
 * waitForData - receiving server, authentication complete, wait for replication datai
               Also sends a plaintext random auth string of our own
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForData() {

   // If data on the socket, should be replication data
   if (_connfd.hasData()) {
//       std::cout << "\n\n----(4) Server: Getting replication data. COMPLETE WOO----\n\n";
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (!getCmdData(buf, c_rep, c_endrep)) {
         std::stringstream msg;
         msg << "Replication data possibly corrupted from" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return;
      }

      // Got the data, save it
      _inputbuf = buf;
      _data_ready = true;

      // Send the acknowledgement and disconnect
      sendData(c_ack);

      if (_verbosity >= 2)
         std::cout << "Successfully received replication data from " << getNodeID() << "\n";


      disconnect();
      _status = s_hasdata;
   }
}


/**********************************************************************************************
 * awaitAwk - waits for the awk that data was received and disconnects
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::awaitAck() {

   // Should have the awk message
   if (_connfd.hasData()) {
//       std::cout << "\n\n----(6) Client: Awaiting Ack. COMPLETE WOO----\n\n";
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return;

      if (findCmd(buf, c_ack) == buf.end())
      {
         std::stringstream msg;
         msg << "Awk expected from data send, received something else. Node:" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
      }
  
      if (_verbosity >= 3)
         std::cout << "Data ack received from " << getNodeID() << ". Disconnecting.\n";

 
      disconnect();
   }
}

/**********************************************************************************************
 * getData - Reads in data from the socket and checks to see if there's an end command to the
 *           message to confirm we got it all
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false if they lost connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getData(std::vector<uint8_t> &buf) {

   std::vector<uint8_t> readbuf;
   size_t count = 0;

   buf.clear();

   while (_connfd.hasData()) {
      // read the data on the socket up to 1024
      count += _connfd.readBytes<uint8_t>(readbuf, 1024);

      // check if we lost connection
      if (readbuf.size() == 0) {
         std::stringstream msg;
         std::string ip_addr;
         msg << "Connection from server " << _node_id << " lost (IP: " << 
                                                         getIPAddrStr(ip_addr) << ")"; 
         _server_log.writeLog(msg.str().c_str());
         disconnect();
         return false;
      }

      buf.insert(buf.end(), readbuf.begin(), readbuf.end());

      // concat the data onto anything we've read before
//      _inputbuf.insert(_inputbuf.end(), readbuf.begin(), readbuf.end());
   }
   return true;
}

/**********************************************************************************************
 * decryptData - Takes in an encrypted buffer in the form IV/Data and decrypts it, replacing
 *               buf with the decrypted info (destroys IV string>
 *
 *    Params: buf - the encrypted string and holds the decrypted data (minus IV)
 *
 **********************************************************************************************/
void TCPConn::decryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);

   // Copy the IV from the incoming stream of data
   init_vector.Assign(buf.data(), iv_size);
   buf.erase(buf.begin(), buf.begin() + iv_size);

   // Decrypt the data
   CFB_Mode<AES>::Decryption decryptor;
   decryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string recovered;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(decryptor, new StringSink(recovered)));

   buf.assign(recovered.begin(), recovered.end());

}


/**********************************************************************************************
 * getEncryptedData - Reads in data from the socket and decrypts it, passing the decrypted
 *                    data back in buf
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false otherwise
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getEncryptedData(std::vector<uint8_t> &buf) {
   // Get the data from the socket
   if (!getData(buf))
      return false;

   decryptData(buf);

   return true; 
}

/**********************************************************************************************
 * findCmd - returns an iterator to the location of a string where a command starts
 * hasCmd - returns true if command was found, false otherwise
 *
 *    Params: buf = the data buffer to look for the command within
 *            cmd - the command string to search for in the data
 *
 *    Returns: iterator - points to cmd position if found, end() if not found
 *
 **********************************************************************************************/

std::vector<uint8_t>::iterator TCPConn::findCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return std::search(buf.begin(), buf.end(), cmd.begin(), cmd.end());
}

bool TCPConn::hasCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return !(findCmd(buf, cmd) == buf.end());
}

/**********************************************************************************************
 * getCmdData - looks for a startcmd and endcmd and returns the data between the two 
 *
 *    Params: buf = the string to search for the tags
 *            startcmd - the command at the beginning of the data sought
 *            endcmd - the command at the end of the data sought
 *
 *    Returns: true if both start and end commands were found, false otherwise
 *
 **********************************************************************************************/

bool TCPConn::getCmdData(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, 
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = buf;
   auto start = findCmd(temp, startcmd);
   auto end = findCmd(temp, endcmd);

   if ((start == temp.end()) || (end == temp.end()) || (start == end))
      return false;

   buf.assign(start + startcmd.size(), end);
   return true;
}

/**********************************************************************************************
 * wrapCmd - wraps the command brackets around the passed-in data
 *
 *    Params: buf = the string to wrap around
 *            startcmd - the command at the beginning of the data
 *            endcmd - the command at the end of the data
 *
 **********************************************************************************************/

void TCPConn::wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd,
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = startcmd;
   temp.insert(temp.end(), buf.begin(), buf.end());
   temp.insert(temp.end(), endcmd.begin(), endcmd.end());

   buf = temp;
}


/**********************************************************************************************
 * getReplData - Returns the data received on the socket and marks the socket as done
 *
 *    Params: buf = the data received
 *
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getInputData(std::vector<uint8_t> &buf) {

   // Returns the replication data off this connection, then prepares it to be removed
   buf = _inputbuf;

   _data_ready = false;
   _status = s_none;
}

/**********************************************************************************************
 * connect - Opens the socket FD, attempting to connect to the remote server
 *
 *    Params:  ip_addr - ip address string to connect to
 *             port - port in host format to connect to
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPConn::connect(const char *ip_addr, unsigned short port) {

   // Set the status to connecting
   _status = s_connecting;

   // Try to connect
   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

// Same as above, but ip_addr and port are in network (big endian) format
void TCPConn::connect(unsigned long ip_addr, unsigned short port) {
   // Set the status to connecting
   _status = s_connecting;

   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

/**********************************************************************************************
 * assignOutgoingData - sets up the connection so that, at the next handleConnection, the data
 *                      is sent to the target server
 *
 *    Params:  data - the data stream to send to the server
 *
 **********************************************************************************************/

void TCPConn::assignOutgoingData(std::vector<uint8_t> &data) {

   _outputbuf.clear();
   _outputbuf = c_rep;
   _outputbuf.insert(_outputbuf.end(), data.begin(), data.end());
   _outputbuf.insert(_outputbuf.end(), c_endrep.begin(), c_endrep.end());
}
 

/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
   _connected = false;
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connected;
   // return _connfd.isOpen(); // This does not work very well
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
const char *TCPConn::getIPAddrStr(std::string &buf) {
   _connfd.getIPAddrStr(buf);
   return buf.c_str();
}

/**********************************************************************************************
 * genBytesForVerify - Generates a random "string" of bytes to be send when initial connection is made
 *
 * Source: https://en.cppreference.com/w/cpp/numeric/random
 *********************************************************************************************/
void TCPConn::genBytesForVerify() {
    // Setup random generator
//    std::cout << "\n\n----Generating random bytes---\n\n";
    std::random_device bar;
    std::default_random_engine foo(bar());
    std::uniform_int_distribution<int>  uniform_distribution(0, 255);

    // Set the string length to 255 bytes
//    this->_gennedAuthStr.resize(255, 0);

    // Convert each position of the string to some random number
    for(int i = 0; i < 255; i++){
        _gennedAuthStr.emplace_back(uniform_distribution(foo));
    }
}

/**********************************************************************************************
 * c_waitForRB() - The client sits here AFTER sending it's SID
 *      Here, the client waits for the server to get the SID then send a random byte string back
 *      Once received, this function encrypts the data and sends it back
 *
 * Source: Code from above
 **********************************************************************************************/
void TCPConn::c_waitForRB(){
    // If data on the socket, should be our random byte authorization string from the host server
    if(_connfd.hasData()){
//        std::cout << "\n\n----(2) Client: Waiting for random bytes from server----\n\n";
        std::vector<uint8_t> buf;

        if(!getData(buf)) { return ;}
        if(!getCmdData(buf, this->c_auth, this->c_endauth)){
            std::stringstream msg;
            msg << "The authorization string from the connecting client is invalid format. Cannot authenticate.";
            this->_server_log.writeLog(msg.str().c_str());
            disconnect();
            return;
        }

        // Received good string
        // Encrypt and send the string
        this->encryptData(buf);
        this->wrapCmd(buf, c_auth, c_endauth);
        this->sendData(buf);

        // Status to wait for the SID
        this->_status = this->c_waitForSID;
    }
}

/**********************************************************************************************
 * c_waitSID() - The client has sent the encrypted string to the server for authentication
 *      We are now waiting for the server to authenticate and send their SID back
 *
 * Source: Code from above
 **********************************************************************************************/
 void TCPConn::c_waitSID(){
     // If data on the socket, should be the server's SID
     if(_connfd.hasData()){
//         std::cout << "\n\n----(3) Client: Bytes good. Sending random bytes to server----\n\n";
         std::vector<uint8_t> buf;

         if(!getData(buf)) { return; }
         if(!getCmdData(buf, this->c_sid, this->c_endsid)){
             std::stringstream msg;
             msg << "The SID from the server is invalid. Cannot connect";
             this->_server_log.writeLog(msg.str().c_str());
             disconnect();
             return;
         }

         std::string node(buf.begin(), buf.end());
         setNodeID(node.c_str());

         // Received an acknowledgement, the SID, from the server
         // Generate and send our random byte string to authenticate them
         this->genBytesForVerify();

         // Send our Random Byte number
         buf.assign(this->_gennedAuthStr.begin(), this->_gennedAuthStr.end());
         this->wrapCmd(buf, this->c_auth, this->c_endauth);
         sendData(buf);

         // We now wait for the encrypted data to come back
         this->_status = c_waitForEBString;
     }
 }

/**********************************************************************************************
* c_waitForEB() - The client has sent a random byte string to be encrypted
*       Here, we are waiting for the server to send the encrypted string back for us to authenticate them
*       Once receieved, we decrypt and check against our originally send string
*
* Source: Code from above
**********************************************************************************************/
void TCPConn::c_waitForEB() {
    // If data on the socket, it should be the server's enrypted version of our _gennedAuthStr
    if(_connfd.hasData()){
//        std::cout << "\n\n----(4) Client: Verifying encrypted bytes----\n\n";
        std::vector<uint8_t> buf;

        if(!getData(buf)) { return; }
        if(!getCmdData(buf, c_auth, c_endauth)){
            std::stringstream msg;
            msg << "Encrypted string from server is invalid. Cannot authenticate.";
            this->_server_log.writeLog(msg.str().c_str());
            disconnect();
            return;
        }

        // Check the decrypted string against what we originally sent.
        this->decryptData(buf);
        // If it matches, transmit data
        // If not, disconnect.
        if(buf == this->_gennedAuthStr){
//            std::cout << "\n\n\n***Client matched encrypted string correctly***\n\n\n";

            // Send Replication data here
            // Send the replication data
            sendData(_outputbuf);

            if (_verbosity >= 3)
                std::cout << "Successfully authenticated connection with " << getNodeID() <<
                          " and sending replication data.\n";

            // Wait for their response
            this->_status = s_waitack;

        }
        else{
            // Reset state machine --> Do I need to set the flag to reset? May cause issue
            this->_status = s_connecting;
            this->disconnect();
        }
    }
}

/**********************************************************************************************
 * s_waitForEB() - The server sits here while waiting for a response from the client
 *      Once EB are received, server decrypts and verifies
 *      If they are the same, send our SID
 *      If they are NOT the same, disconnect
 *
 * Source: Code from above
 **********************************************************************************************/

void TCPConn::s_waitForEB(){
    // If data on the socket, it should be the client's encrypted version of our _gennedAuthStr
    if(_connfd.hasData()){
//        std::cout << "\n\n----(2) Server: Received encrypted bytes from client. Verifying----\n\n";
        std::vector<uint8_t> buf;

        if(!getData(buf)) { return; }
        if(!getCmdData(buf, c_auth, c_endauth)){
            std::stringstream msg;
            msg << "Encrypted string from client is invalid. Cannot authenticate.";
            this->_server_log.writeLog(msg.str().c_str());
            disconnect();
            return;
        }

        // Check if the decrypted string is what we originally sent
        // If match, wait for the client's random bytes string
        // Otherwise, do not connect
//        std::cout << "Checking the strings\n";
        this->decryptData(buf);
        if(buf == this->_gennedAuthStr){
//            std::cout << "\n\n\n***Server matched encrypted string correctly***\n\n\n";

            // Send our SID for an ack purpose
            buf.assign(this->_svr_id.begin(), this->_svr_id.end());
            this->wrapCmd(buf, c_sid, c_endsid);
            sendData(buf);

            this->_status = s_waitForRBString;
        }
        else{
//            std::cout << "\n\n\n-Server: Strings did not match-\n\n\n";
            this->_status = s_connected;
            this->disconnect();
        }
    }
}

/**********************************************************************************************
 * s_waitForRB() - The server has fully authenticated the client
 *      Now, we allow the client to authenticate us
 *      Here, we wait for the client to send us a RB string to encrypt and send back
 *
 * Source: Code from above
 **********************************************************************************************/
 void TCPConn::s_waitForRB() {
     // If data on socket, it should be the client's random byte string
     if(_connfd.hasData()){
//         std::cout << "\n\n----(3) Server: Waiting for random bytes from client----\n\n";
         std::vector<uint8_t> buf;

         if(!getData(buf)) { return; }
         if(!getCmdData(buf, c_auth, c_endauth)){
             std::stringstream msg;
             msg << "Random Byte string from client is invalid. Cannot authenticate.";
             this->_server_log.writeLog(msg.str().c_str());
             disconnect();
             return;
         }

         // Encrypt the string, wrap, send back
         this->encryptData(buf);
         this->wrapCmd(buf, c_auth, c_endauth);
         this->sendData(buf);

         this->_status = s_datarx;
     }
 }