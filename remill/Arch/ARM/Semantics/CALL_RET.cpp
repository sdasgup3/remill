/*
 * CALL_RET.cpp
 *
 *  Created on: May 10, 2017
 *      Author: akshayk
 */

DEF_SEM(RET) {
  return memory;
}

DEF_SEM(STP) {
  return memory;
}


//DEF_ISEL_32or64(RET_NEAR_IMMw, RET_IMM);
DEF_ISEL(RET) = RET;
DEF_ISEL(STP) = STP;
