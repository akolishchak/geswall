//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __reentrance_h__
#define __reentrance_h__

namespace ReEntrance {

void Init(void);
void Release(void);

class Check {
public:
	Check();
	~Check();
	bool IsTrue(void);
private:
	bool CheckResult;
};
 
}; // namespace ReEntrance {


#endif // __reentrance_h__