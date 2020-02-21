#include <iostream>
#include <string>
#include <random>

int main(){
   std::string _authstr;

   std::random_device r;
   
   std::default_random_engine el(r());
   std::uniform_int_distribution<int> uniform_dist(0,255);
   int mean = uniform_dist(el);

   for(int i = 0; i < mean; i++){
       _authstr = _authstr + std::to_string(i);
   }
    std::cout << "String: " << _authstr << "\n";


   for(int i = 0; i < mean; i++){
       _authstr[i] = uniform_dist(el);
   }

   std::cout << "Number: " << mean << "\n";
   std::cout << "String: " << _authstr << "\n";

   return 0;
}
