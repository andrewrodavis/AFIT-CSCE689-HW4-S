//
// Created by andre on 2/27/2020.
//

#ifndef AFIT_CSCE689_HW4_S_HANDLEDUPLICATION_H
#define AFIT_CSCE689_HW4_S_HANDLEDUPLICATION_H
#pragma once

#include <DronePlotDB.h>

class handleDuplication {
public:
    handleDuplication(DronePlotDB &plotDB);
    ~handleDuplication();
    void deleteDuplicates();
    void testPrint();

private:
    DronePlotDB &_plotDB;
};


#endif //AFIT_CSCE689_HW4_S_HANDLEDUPLICATION_H
