//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _CONFIG_CONFIGURATOR_H_
 #define _CONFIG_CONFIGURATOR_H_

#include <boost/smart_ptr.hpp> 

#include "configexception.h"
#include "inode.h"

namespace config {

class Configurator;


class Configurator
{
  //
  // types
  //
  public:
   typedef INode::PtrToINode   PtrToINode;
  protected:
  private:

  //
  // methods
  //
  public:
   static PtrToINode getServiceNode ();
   static PtrToINode getStorageNode ();
   static PtrToINode getDriverNode ();
   static PtrToINode getGswlPolicyNode ();
   static PtrToINode getProcessMarkerNode ();
   static PtrToINode getUiNode ();
   static PtrToINode getUpdateNode ();
   static PtrToINode getGPNode ();
   static PtrToINode getLogWindowNode ();
   static PtrToINode getVendorNode ();
   static PtrToINode getNotificatorNode ();
   static PtrToINode getTrialManagerNode ();
   static PtrToINode getAppStatNode ();

  protected:
            Configurator () {};
   virtual ~Configurator () {};

            Configurator (const Configurator& right) {};
   Configurator& operator= (const Configurator& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // Configurator

} // namespace config {

#endif // _CONFIG_CONFIGURATOR_H_