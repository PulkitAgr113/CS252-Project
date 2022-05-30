#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <tuple>
#include <algorithm>
#include <fstream>
#include <unistd.h>
#include <dirent.h>
#include <string>
#include <filesystem>
using namespace std;


/**************************************************************************
 Code for MD5 calculation begins here
***************************************************************************/

class MD5
{
public:
  typedef unsigned int size_type; // must be 32bit
 
  MD5();
  MD5(const std::string& text);
  void update(const unsigned char *buf, size_type length);
  void update(const char *buf, size_type length);
  MD5& finalize();
  std::string hexdigest() const;
  friend std::ostream& operator<<(std::ostream&, MD5 md5);
 
private:
  void init();
  typedef unsigned char uint1; //  8bit
  typedef unsigned int uint4;  // 32bit
  enum {blocksize = 64}; // VC6 won't eat a const static int here
 
  void transform(const uint1 block[blocksize]);
  static void decode(uint4 output[], const uint1 input[], size_type len);
  static void encode(uint1 output[], const uint4 input[], size_type len);
 
  bool finalized;
  uint1 buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk
  uint4 count[2];   // 64bit counter for number of bits (lo, hi)
  uint4 state[4];   // digest so far
  uint1 digest[16]; // the result
 
  // low level logic operations
  static inline uint4 F(uint4 x, uint4 y, uint4 z);
  static inline uint4 G(uint4 x, uint4 y, uint4 z);
  static inline uint4 H(uint4 x, uint4 y, uint4 z);
  static inline uint4 I(uint4 x, uint4 y, uint4 z);
  static inline uint4 rotate_left(uint4 x, int n);
  static inline void FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
  static inline void GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
  static inline void HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
  static inline void II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
};
 
std::string md5(const std::string str);


#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

// F, G, H and I are basic MD5 functions.
inline MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) {
  return x&y | ~x&z;
}
 
inline MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) {
  return x&z | y&~z;
}
 
inline MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) {
  return x^y^z;
}
 
inline MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) {
  return y ^ (x | ~z);
}
 
// rotate_left rotates x left n bits.
inline MD5::uint4 MD5::rotate_left(uint4 x, int n) {
  return (x << n) | (x >> (32-n));
}
 
// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline void MD5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a+ F(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
  a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
}

// default ctor, just initailize
MD5::MD5()
{
  init();
}

// nifty shortcut ctor, compute MD5 for string and finalize it right away
MD5::MD5(const std::string &text)
{
  init();
  update(text.c_str(), text.length());
  finalize();
}

void MD5::init()
{
  finalized=false;
 
  count[0] = 0;
  count[1] = 0;
 
  // load magic initialization constants.
  state[0] = 0x67452301;
  state[1] = 0xefcdab89;
  state[2] = 0x98badcfe;
  state[3] = 0x10325476;
}

// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void MD5::decode(uint4 output[], const uint1 input[], size_type len)
{
  for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
      (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
}

// encodes input (uint4) into output (unsigned char). Assumes len is
// a multiple of 4.
void MD5::encode(uint1 output[], const uint4 input[], size_type len)
{
  for (size_type i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = input[i] & 0xff;
    output[j+1] = (input[i] >> 8) & 0xff;
    output[j+2] = (input[i] >> 16) & 0xff;
    output[j+3] = (input[i] >> 24) & 0xff;
  }
}

// apply MD5 algo on a block
void MD5::transform(const uint1 block[blocksize])
{
  uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
  decode (x, block, blocksize);
 
  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
 
  /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
 
  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */
 
  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */
 
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
 
  // Zeroize sensitive information.
  memset(x, 0, sizeof x);
}

// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void MD5::update(const unsigned char input[], size_type length)
{
  // compute number of bytes mod 64
  size_type index = count[0] / 8 % blocksize;
 
  // Update number of bits
  if ((count[0] += (length << 3)) < (length << 3))
    count[1]++;
  count[1] += (length >> 29);
 
  // number of bytes we need to fill in buffer
  size_type firstpart = 64 - index;
 
  size_type i;
 
  // transform as many times as possible.
  if (length >= firstpart)
  {
    // fill buffer first, transform
    memcpy(&buffer[index], input, firstpart);
    transform(buffer);
 
    // transform chunks of blocksize (64 bytes)
    for (i = firstpart; i + blocksize <= length; i += blocksize)
      transform(&input[i]);
 
    index = 0;
  }
  else
    i = 0;
 
  // buffer remaining input
  memcpy(&buffer[index], &input[i], length-i);
}

// for convenience provide a verson with signed char
void MD5::update(const char input[], size_type length)
{
  update((const unsigned char*)input, length);
}

// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
MD5& MD5::finalize()
{
  static unsigned char padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
 
  if (!finalized) {
    // Save number of bits
    unsigned char bits[8];
    encode(bits, count, 8);
 
    // pad out to 56 mod 64.
    size_type index = count[0] / 8 % 64;
    size_type padLen = (index < 56) ? (56 - index) : (120 - index);
    update(padding, padLen);
 
    // Append length (before padding)
    update(bits, 8);
 
    // Store state in digest
    encode(digest, state, 16);
 
    // Zeroize sensitive information.
    memset(buffer, 0, sizeof buffer);
    memset(count, 0, sizeof count);
 
    finalized=true;
  }
 
  return *this;
}

// return hex representation of digest as string
std::string MD5::hexdigest() const
{
  if (!finalized)
    return "";
 
  char buf[33];
  for (int i=0; i<16; i++)
    sprintf(buf+i*2, "%02x", digest[i]);
  buf[32]=0;
 
  return std::string(buf);
}

std::ostream& operator<<(std::ostream& out, MD5 md5)
{
  return out << md5.hexdigest();
}

std::string md5(const std::string str)
{
    MD5 md5 = MD5(str);
 
    return md5.hexdigest();
}

/**************************************************************************
 Code for MD5 calculation ends here
***************************************************************************/


int main(int argc, char** argv){

    if(argc != 3) {
        cout << "Enter 2 arguments - Config File and Directory Path\n";
        exit(0);
    }

    string client_no;
    string port;
    string unique_id;

    int no_of_neighbors;
    int no_of_neighbors_lesser = 0;
    int no_of_neighbors_greater = 0;
    vector <pair <string, string> > neighbors;

    vector <tuple <int, string, string> > neighbor_initial_data;
    int no_of_connected_neighbors_lesser = 0;
    int no_of_connected_neighbors_greater = 0;

    string no_of_files;
    vector <string> files;

    string config_file = argv[1];
    char* dir_path = argv[2];

    ifstream fin(config_file);

    fin >> client_no >> port >> unique_id;
    fin >> no_of_neighbors;

    for ( int neighbor = 1; neighbor <= no_of_neighbors; neighbor ++ ) {
        string neighbor_no;
        string neighbor_port;

        fin >> neighbor_no >> neighbor_port;
        if(stoi(neighbor_no) < stoi(client_no)) no_of_neighbors_lesser++;
        else no_of_neighbors_greater++;
        neighbors.push_back({neighbor_no, neighbor_port});
    }
    
    fin >> no_of_files;
    for ( int file = 1; file <= stoi(no_of_files); file ++ ) {
        string file_name;

        fin >> file_name;
        files.push_back(file_name);
    }

    sort(files.begin(), files.end());
    vector <int> file_unique_id (stoi(no_of_files), -1);
    vector <string> MD5 (stoi(no_of_files), "0");
    vector <string> filenames;

    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (dir_path)) != NULL) {
        while ((ent = readdir (dir)) != NULL) {
            string file_name = ent -> d_name;
            if (file_name != "." && file_name != ".." && file_name != "Downloaded") {
                filenames.push_back(file_name);
                cout << file_name << "\n";
            }
        }
        closedir (dir);
    }
   
    else {
        perror ("");
        return EXIT_FAILURE;
    }

    sort(filenames.begin(), filenames.end());

    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo hints, *res;
    int sockfd, new_fd;

    // first, load up address structs with getaddrinfo():

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    //char* port1=&port[0];
    getaddrinfo(NULL, &port[0], &hints, &res);

    // make a socket:

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sockfd == 0) {
        cout << "Error in creating socket\n";
    }

    // bind it to the port we passed in to getaddrinfo():

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    if(bind(sockfd, res->ai_addr, res->ai_addrlen)<0){
        cout<<"Binding Error"<<endl;
    }

    if(listen(sockfd, 10)<0){
        cout<<"Error in listening"<<endl;
    }

    string random_send = "Wasting a turn";
    char random_read[100] = {0};

    while (no_of_connected_neighbors_greater < no_of_neighbors_greater) {
    
        // now accept an incoming connection:

        addr_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if(new_fd < 0){
            cout<<"Error in accepting"<<endl;
        }
        no_of_connected_neighbors_greater ++;
        char buffer[3][100] = {0};
        char num_neighbor_files[100]={0};
        char yes_or_no[100] = {0};
        
        read(new_fd, buffer[0], 100);
        send(new_fd, &client_no[0], client_no.length(), 0);
        read(new_fd, buffer[1], 100);
        send(new_fd, &port[0], port.length(), 0);
        read(new_fd, buffer[2], 100);
        send(new_fd, &unique_id[0], unique_id.length(), 0);
        read(new_fd, num_neighbor_files, 100);
        send(new_fd, &no_of_files[0], no_of_files.length(), 0);
        
        for(int nf = 0; nf < strtol(num_neighbor_files, nullptr, 10); nf ++) {
            char neighbor_filename[100]={0};
            read(new_fd, neighbor_filename, 100);
            bool found = binary_search(filenames.begin(), filenames.end(), (string) neighbor_filename);
            if (found) send(new_fd, "Y", 1, 0);
            else send(new_fd, "N", 1, 0);
        }

        read(new_fd, random_read, 100);
        for(int nf = 0; nf < stoi(no_of_files); nf ++) {
            send(new_fd, &(files[nf])[0], files[nf].length(), 0);
            read(new_fd, yes_or_no, 100);
            if((string) yes_or_no == "Y"){
                int unique_id_neigh = strtol(buffer[2], nullptr, 10);
                if(file_unique_id[nf] < 0) file_unique_id[nf] = unique_id_neigh;
                else if(file_unique_id[nf] > unique_id_neigh) file_unique_id[nf] = unique_id_neigh;
            }
        }

        close(new_fd);
        neighbor_initial_data.push_back(make_tuple(strtol(buffer[0], nullptr, 10), (string) buffer[1], (string) buffer[2]));
    }

    for (int neigh = 0; neigh < no_of_neighbors; neigh ++ ) {
        string neighbor_id = neighbors[neigh].first;
        string neighbor_port = neighbors[neigh].second;
        if(stoi(neighbor_id) > stoi(client_no)) continue;

        
        int neighbor_sockfd;
        struct addrinfo neighbor_hints, *neighbor_res;
        memset(&neighbor_hints, 0, sizeof neighbor_hints);
        neighbor_hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
        neighbor_hints.ai_socktype = SOCK_STREAM;
        // neighbor_hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
        
        getaddrinfo("127.0.0.1", &neighbor_port[0], &neighbor_hints, &neighbor_res);
        neighbor_sockfd = socket(neighbor_res->ai_family, neighbor_res->ai_socktype, neighbor_res->ai_protocol);
        
        if(neighbor_sockfd == 0){
            cout<<"Error in creating neighbour socket"<<endl;
        }

        int connected =-1;

        while(connected ==-1){
            connected = connect(neighbor_sockfd, neighbor_res -> ai_addr, neighbor_res -> ai_addrlen);
        }

        no_of_connected_neighbors_lesser ++;
        char buffer[3][1024] = {0};
        char num_neighbor_files[100]={0};
       
        char yes_or_no[100] = {0};

        send(neighbor_sockfd, &client_no[0], client_no.length(), 0);
        read(neighbor_sockfd, buffer[0], 100);
        send(neighbor_sockfd, &port[0], port.length(), 0);
        read(neighbor_sockfd, buffer[1], 100);
        send(neighbor_sockfd, &unique_id[0], unique_id.length(), 0);
        read(neighbor_sockfd, buffer[2], 100);
        send(neighbor_sockfd, &no_of_files[0], no_of_files.length(), 0);
        read(neighbor_sockfd, num_neighbor_files, 100);

        for(int nf = 0; nf < stoi(no_of_files); nf ++) {
            send(neighbor_sockfd, &(files[nf])[0], files[nf].length(), 0);
            read(neighbor_sockfd, yes_or_no, 100);
            if((string) yes_or_no == "Y"){
                int unique_id_neigh = strtol(buffer[2], nullptr, 10);
                if(file_unique_id[nf] < 0) file_unique_id[nf] = unique_id_neigh;
                else if(file_unique_id[nf] > unique_id_neigh) file_unique_id[nf] = unique_id_neigh;
            }
        }

        send(neighbor_sockfd, &random_send[0], random_send.length(), 0);
        for(int nf = 0; nf < strtol(num_neighbor_files, nullptr, 10); nf ++) {
            char neighbor_filename[100]={0};
            read(neighbor_sockfd, neighbor_filename, 100);
            bool found = binary_search(filenames.begin(), filenames.end(), (string) neighbor_filename);
            if (found) send(neighbor_sockfd, "Y", 1, 0);
            else send(neighbor_sockfd, "N", 1, 0);
        }

        close(neighbor_sockfd);
        neighbor_initial_data.push_back(make_tuple(strtol(buffer[0], nullptr, 10), (string) buffer[1], (string) buffer[2]));
    }

    sort(neighbor_initial_data.begin(), neighbor_initial_data.end());
    for (auto elem: neighbor_initial_data) {
        cout << "Connected to " << get<0>(elem) << " with unique-ID " << get<2>(elem) << " on port " << get<1>(elem) << "\n";
    }

    no_of_connected_neighbors_greater = 0;
    no_of_connected_neighbors_lesser = 0;

    while (no_of_connected_neighbors_lesser < no_of_neighbors_lesser) {
    
        // now accept an incoming connection:

        addr_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if(new_fd < 0){
            cout<<"Error in accepting"<<endl;
        }
        no_of_connected_neighbors_lesser ++;
        char buffer[100] = {0};
        char num_neighbor_files[100]={0};
                  
        read(new_fd, buffer, 100);
        send(new_fd, &unique_id[0], unique_id.length(), 0);
        vector<string> files_wanted;

        for(int nf = 0; nf < stoi(no_of_files); nf ++) {
            if(strtol(buffer, nullptr, 10) == file_unique_id[nf]) files_wanted.push_back(files[nf]);
        }

        read(new_fd, num_neighbor_files, 100);
        send(new_fd, &to_string(files_wanted.size())[0], to_string(files_wanted.size()).length(), 0);
        
        for(int nf = 0; nf < strtol(num_neighbor_files, nullptr, 10); nf ++) {
            char name_of_file[100] = {0};  
            read(new_fd, name_of_file, 100);

            FILE *fin;
            fin = fopen(&((string) dir_path + (string) name_of_file)[0], "r");
            fseek(fin, 0L, SEEK_END);
            long file_size = ftell(fin);
            fseek(fin, 0L, SEEK_SET);
            send(new_fd, &to_string(file_size)[0], to_string(file_size).length(), 0);

            char* buf = (char*) calloc(file_size, sizeof(char));
            fread(buf, sizeof(char), file_size, fin);
            fclose(fin);

            long bytes_left = file_size;  
            read(new_fd, random_read, 100);
            while(bytes_left > 0) {
                send(new_fd, buf + file_size - bytes_left, min((long) 1000, bytes_left), 0);
                char bytes_sent[100] = {0};
                read(new_fd, bytes_sent, 100);
                bytes_left -= strtol(bytes_sent, nullptr, 10);
            }
            send(new_fd, &random_send[0], random_send.length(), 0);
        }

        for(int fw = 0; fw < (int) files_wanted.size(); fw ++) {
            string file_name = files_wanted[fw];
            read(new_fd, random_read, 100);
            send(new_fd, &file_name[0], file_name.length(), 0);
            char file_size[100] = {0};
            read(new_fd, file_size, 100);
            send(new_fd, &random_send[0], random_send.length(), 0);

            long bytes_left = strtol(file_size, nullptr, 10);
            char* buf = (char*) calloc(bytes_left, sizeof(char));
            while(bytes_left > 0) {
                int read_file_size = read(new_fd, buf + strtol(file_size, nullptr, 10) - bytes_left, bytes_left);
                bytes_left -= read_file_size;
                send(new_fd, &to_string(read_file_size)[0], to_string(read_file_size).length(), 0);
            }

            filesystem::create_directory((string) dir_path + "Downloaded");
            ofstream fout((string) dir_path + "/Downloaded/" + file_name, ios::out | ios::binary);
            fout.write(buf, strtol(file_size, nullptr, 10));

            string str = "";
            for (int r = 0; r < strtol(file_size, nullptr, 10); r ++) {
                str += buf[r];
            }

            int ind = find(files.begin(), files.end(), file_name) - files.begin();
            MD5[ind] = md5(str);
        }

        close(new_fd);
    }

    for (int neigh = 0; neigh < no_of_neighbors; neigh ++ ) {
        string neighbor_id = neighbors[neigh].first;
        string neighbor_port = neighbors[neigh].second;
        if(stoi(neighbor_id) < stoi(client_no)) continue;
        
        int neighbor_sockfd;
        struct addrinfo neighbor_hints, *neighbor_res;
        memset(&neighbor_hints, 0, sizeof neighbor_hints);
        neighbor_hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
        neighbor_hints.ai_socktype = SOCK_STREAM;
        // neighbor_hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
        
        getaddrinfo("127.0.0.1", &neighbor_port[0], &neighbor_hints, &neighbor_res);
        neighbor_sockfd = socket(neighbor_res->ai_family, neighbor_res->ai_socktype, neighbor_res->ai_protocol);
        
        if(neighbor_sockfd == 0){
            cout<<"Error in creating neighbour socket"<<endl;
        }

        int connected =-1;

        while(connected ==-1){
            connected = connect(neighbor_sockfd, neighbor_res -> ai_addr, neighbor_res -> ai_addrlen);
        }

        no_of_connected_neighbors_greater ++;
        char buffer[100] = {0};
        char num_neighbor_files[100]={0};
                  
        send(neighbor_sockfd, &unique_id[0], unique_id.length(), 0);
        read(neighbor_sockfd, buffer, 100);
        vector<string> files_wanted;

        for(int nf = 0; nf < stoi(no_of_files); nf ++) {
            if(strtol(buffer, nullptr, 10) == file_unique_id[nf]) files_wanted.push_back(files[nf]);
        }

        send(neighbor_sockfd, &to_string(files_wanted.size())[0], to_string(files_wanted.size()).length(), 0);
        read(neighbor_sockfd, num_neighbor_files, 100);

        for(int fw = 0; fw < (int) files_wanted.size(); fw ++) {
            string file_name = files_wanted[fw];
            send(neighbor_sockfd, &file_name[0], file_name.length(), 0);
            char file_size[100] = {0};
            read(neighbor_sockfd, file_size, 100);
            send(neighbor_sockfd, &random_send[0], random_send.length(), 0);

            long bytes_left = strtol(file_size, nullptr, 10);
            char* buf = (char*) calloc(bytes_left, sizeof(char));
            while(bytes_left > 0) {
                int read_file_size = read(neighbor_sockfd, buf + strtol(file_size, nullptr, 10) - bytes_left, bytes_left);
                bytes_left -= read_file_size;
                send(neighbor_sockfd, &to_string(read_file_size)[0], to_string(read_file_size).length(), 0);
            }

            read(neighbor_sockfd, random_read, 100);

            filesystem::create_directory((string) dir_path + "Downloaded");
            ofstream fout((string) dir_path + "Downloaded/" + file_name, ios::out | ios::binary);
            fout.write(buf, strtol(file_size, nullptr, 10));

            string str = "";
            for (int r = 0; r < strtol(file_size, nullptr, 10); r ++) {
                str += buf[r];
            }

            int ind = find(files.begin(), files.end(), file_name) - files.begin();
            MD5[ind] = md5(str);
        }

        for(int nf = 0; nf < strtol(num_neighbor_files, nullptr, 10); nf ++) {
            send(neighbor_sockfd, &random_send[0], random_send.length(), 0);
            char name_of_file[100] = {0};  
            read(neighbor_sockfd, name_of_file, 100);

            FILE *fin;
            fin = fopen(&((string) dir_path + (string) name_of_file)[0], "r");
            fseek(fin, 0L, SEEK_END);
            long file_size = ftell(fin);
            fseek(fin, 0L, SEEK_SET);
            send(neighbor_sockfd, &to_string(file_size)[0], to_string(file_size).length(), 0);

            char* buf = (char*) calloc(file_size, sizeof(char));
            fread(buf, sizeof(char), file_size, fin);
            fclose(fin);

            long bytes_left = file_size;  
            read(neighbor_sockfd, random_read, 100);
            while(bytes_left > 0) {
                send(neighbor_sockfd, buf + file_size - bytes_left, min((long) 1000, bytes_left), 0);
                char bytes_sent[100] = {0};
                read(neighbor_sockfd, bytes_sent, 100);
                bytes_left -= strtol(bytes_sent, nullptr, 10);
            }

        }

        close(neighbor_sockfd);
    }

    for(int nf = 0; nf < stoi(no_of_files); nf ++) {
        int unique_id_neigh = file_unique_id[nf];
        int depth = 1;
        if(unique_id_neigh < 0) {
            depth = 0;
            unique_id_neigh = 0;
        }
        cout << "Found " << files[nf] << " at " << unique_id_neigh << " with MD5 " << MD5[nf] << " at depth " << depth << "\n";
    }

    close(sockfd);
    
}
