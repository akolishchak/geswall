//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __cpprt_h__
#define __cpprt_h__

//
// new and delete operators 
//

#ifdef _AMD64_
inline void * __cdecl operator new(size_t Size)
#else
inline void * __cdecl operator new(unsigned int Size)
#endif
{
	return Size ? ExAllocatePoolWithTag(NonPagedPool, Size, ' wen') : NULL;
}

#ifdef _AMD64_
inline void * __cdecl operator new(size_t Size, POOL_TYPE Type)
#else
inline void * __cdecl operator new(unsigned int Size, POOL_TYPE Type)
#endif
{ 
	return Size ? ExAllocatePoolWithTag(Type, Size, ' wen') : NULL;
}

#ifdef _AMD64_
inline void * __cdecl operator new(size_t Size, POOL_TYPE Type, size_t OptionSize)
#else
inline void * __cdecl operator new(unsigned int Size, POOL_TYPE Type, unsigned int OptionSize)
#endif
{ 
	return Size ? ExAllocatePoolWithTag(Type, Size + OptionSize, ' wen') : NULL;
}

inline void __cdecl operator delete(void* Pointer)
{ 
	if (Pointer) ExFreePool(Pointer);
}

inline void __cdecl operator delete [] (void* Pointer)
{ 
	if (Pointer) ExFreePool(Pointer);
}

#endif	// __cpprt_h__

