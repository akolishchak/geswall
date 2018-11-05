//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _gswui_toolwnd_colors_h_
 #define _gswui_toolwnd_colors_h_

#include "config/configurator.h"
#include "gesruledef.h"

namespace gswui {
namespace toolwnd {


class Colors;


class Colors
{
  //
  // types
  //
  public:
  protected:
  private:

  //
  // methods
  //
  public:
   Colors () 
    : m_trusted (RGB (-1, -1, -1)),    // green
      m_untrusted (RGB (132, 0, 0)),   // dark red
      m_isolated (RGB (128, 255, 0)),  // green
      m_current (m_trusted)
   {
     
   } // Colors

   virtual ~Colors () 
   {
   
   } // ~Colors
   
   void reloadSetting ()
   {
     config::Configurator::PtrToINode params = config::Configurator::getProcessMarkerNode ();
     if (NULL != params.get ())
     {
       unsigned int color;
       if (0 != (color = params->getUInt (L"untrustedColor")))
         m_untrusted = RGB (GetRValue (color), GetGValue (color), GetBValue (color));
       else
         params->setUInt (L"untrustedColor", m_untrusted);
         
       if (0 != (color = params->getUInt (L"isolatedColor16")))  
         m_isolated = RGB (GetRValue (color), GetGValue (color), GetBValue (color));
       else
         params->setUInt (L"isolatedColor16", m_isolated);  
     } // if (NULL != params.get ())
   }

   void refreshCurrentColor (GesRule::ModelType processState)
   {
     setCurrentColor (getColor (processState));
   } // refreshCurrentColor

   void setCurrentColor (COLORREF color)
   {
     m_current = color;
   } // setCurrentColor

   COLORREF getCurrentColor () const
   {
     return m_current;
   } // getCurrentColor
   
   COLORREF getTrustedColor () const
   {
     return m_trusted;
   } // getTrustedColor
   
   COLORREF getUntrustedColor () const
   {
     return m_untrusted;
   } // getUntrustedColor
   
   COLORREF getIsolatedColor () const
   {
     return m_isolated;
   } // getIsolatedColor
   
   bool is_trusted_state (GesRule::ModelType processState)
   {
     bool result = false;
     
     switch (processState)
     {
       case GesRule::modUndefined:
            result = false;
            break;
       case GesRule::modUntrusted:
            result = false;
            break;
       case GesRule::modThreatPoint:
            result = false;
            break;
       case GesRule::modTrusted:
            result = true;
            break;
       case GesRule::modTCB:
            result = true;
            break;
       default:
            result = false;
            break;
     } // switch
     
     return result;
   } // is_trusted_state

   COLORREF getColor (GesRule::ModelType processState)
   {
     COLORREF current = m_untrusted;

     switch (processState)
     {
       case GesRule::modUndefined:
            current = m_untrusted;
            break;
       case GesRule::modUntrusted:
            current = m_untrusted;
            break;
       case GesRule::modThreatPoint:
            current = m_isolated;
            break;
       case GesRule::modTrusted:
            current = m_trusted;
            break;
       case GesRule::modTCB:
            current = m_trusted;
            break;
       default:
            current = m_untrusted;
            break;
     } // switch

     return current;
   } // getColor

   void setIsolatedColor (COLORREF color)
   {
     m_isolated = color;
     config::Configurator::PtrToINode params = config::Configurator::getProcessMarkerNode ();
     if (NULL != params.get ())
       params->setUInt (L"isolatedColor16", m_isolated);  
   } // setIsolatedColor
   
   void setUntrustedColor (COLORREF color)
   {
     m_untrusted = color;
     config::Configurator::PtrToINode params = config::Configurator::getProcessMarkerNode ();
     if (NULL != params.get ())
       params->setUInt (L"untrustedColor", m_untrusted);
   } // setUntrustedColor

  protected:
            Colors (const Colors& right) {};
   Colors& operator= (const Colors& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
   COLORREF m_trusted;
   COLORREF m_untrusted;
   COLORREF m_isolated;

   COLORREF m_current;

  private:
}; // Colors

} // namespace toolwnd {
} // namespace gswui {


#endif // _gswui_toolwnd_colors_h_