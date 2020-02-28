//
// Created by andrew on 2/27/2020.
//

#include "handleDuplication.h"
#include <iostream>

handleDuplication::handleDuplication(DronePlotDB &plotDB) : _plotDB(plotDB) {}
handleDuplication::~handleDuplication() {}

/*********************************************************************************************
 * findDuplicates - This iterates over the stored DronePlotDB object and looks for duplicates.
 *      If one is found, the index is stored in the duplicateIndices list
 *
 *********************************************************************************************/
void handleDuplication::findDuplicates() {
    int i_index = 0;
//    this->duplicateIndices.clear(); // Reset Var. Do not do if checking once

    for(auto i = this->_plotDB.begin(); i != this->_plotDB.end(); i++){
        for(auto j = std::next(i, 1); j != this->_plotDB.end(); j++){
            // Check if: Lat's are same, Long's are same, Drone ID's are same, and Node ID's are different
            if( (i->drone_id == j->drone_id) && (i->node_id != j->node_id) && (i->latitude == j->latitude) && (i->longitude == j->longitude)){
                this->duplicateIndices.push_back((i_index));
                break;
            }
        }
        i_index++;
    }
}

/*********************************************************************************************
 * handleSkew - Does something with the time skews, but I am unsure what to do once found
 *
 *********************************************************************************************/
 void handleDuplication::handleSkew() {

 }
/*********************************************************************************************
 * deleteDuplicates - This iterates over the stored DronePlotDB object and delete duplicate data
 *      based on similar lat/long positions and time
 *
 *********************************************************************************************/
void handleDuplication::deleteDuplicates() {
    // Iterate over the list
    for(int i = 0; i < this->duplicateIndices.size(); i++){
        this->_plotDB.erase(i);
    }
}

/*********************************************************************************************
 * testPrint - Prints information to check that this object is being used and coded correctly
 *********************************************************************************************/
void handleDuplication::testPrint() {
    std::cout << "\n\n----Printing DB List----\n\n";

    for(auto i = this->_plotDB.begin(); i != this->_plotDB.end(); i++) {
        std::cout << "----Plot\n";
        std::cout << "--------ID: " << i->node_id << " : " << i->drone_id << "\n";
        std::cout << "--------Lat Long " << i->latitude << " : " << i->longitude << "\n";
        std::cout << "--------Time: " << i->timestamp << "\n";
    }
}

