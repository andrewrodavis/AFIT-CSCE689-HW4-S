//
// Created by andrew on 2/27/2020.
//

#include "handleDuplication.h"
#include <iostream>

handleDuplication::handleDuplication(DronePlotDB &plotDB) : _plotDB(plotDB) {}
handleDuplication::~handleDuplication() {}

/*********************************************************************************************
 * testPrint - Prints information to check that this object is being used and coded correctly
 *********************************************************************************************/
 void handleDuplication::testPrint() {
     std::cout << "\n\n-------------\n";

     for(auto dbObj : this->_plotDB){
         std::cout << "Obj ID: " << dbObj.node_id << "\n";
     }
     std::cout << "----------\n\n\n";
 }
/*********************************************************************************************
 * deleteDuplicates - This iterates over the stored DronePlotDB object and delete duplicate data
 *      based on similar lat/long positions and time
 *
 *********************************************************************************************/
void handleDuplication::deleteDuplicates() {
    // Iterate over the list
    for(auto it = this->_plotDB.begin(); it != this->_plotDB.end(); it++){
        for(auto itT = this->_plotDB.begin(); itT != this->_plotDB.end(); itT++){

        }
    }
}

