//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswmmc_interface_common_h_
 #define _gswmmc_interface_common_h_

namespace gswmmc {

template <typename interface_type>
struct interface_finalizer_t
{
    void operator () (interface_type object)
    {
        if (NULL != object)
            object->Release ();
    }
}; // struct interface_finalizer_t

template <typename interface_type>
interface_finalizer_t <interface_type>
make_interface_finalizer (const interface_type& interface_object)
{
    return interface_finalizer_t<interface_type> ();
} // make_interface_finalizer

}; // namespace gswmmc {

#endif // _gswmmc_interface_common_h_

