#include <iostream>
#include <string>
#include <random>

int main(){
    std::vector<uint8_t> _gennedAuthStr;
        // Setup random generator
        std::random_device bar;
        std::default_random_engine foo(bar());
        std::uniform_int_distribution<int>  uniform_distribution(0, 255);

        // Convert each position of the string to some random number
        for(int i = 0; i < 255; i++){
            _gennedAuthStr.emplace_back(uniform_distribution(foo));
        }

        for(auto a : _gennedAuthStr){
            std::cout << a << "\n";
        }
    std::cout << "size: " << _gennedAuthStr.size() << "\n";
    return 0;
}
