//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _interface_gswui_log_view_h_
 #define _interface_gswui_log_view_h_

#include <string>

#include <boost/smart_ptr.hpp>
 
namespace gswui {
namespace logwnd {

class log_view;

typedef std::wstring  wstring;

class log_view
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
            log_view () {};
   virtual ~log_view () {};

   virtual  bool create (HWND parent_window, int control_id) = 0;
   virtual  void destroy () = 0;

   virtual  void resize (int x, int y, int width, int height) = 0;
   virtual  void repaint () = 0;
   virtual  void set_background_color (COLORREF color) = 0;

   virtual  void   set_max_queue_size (size_t max_queue_size) = 0;
   virtual  size_t get_max_queue_size () = 0;

   virtual  void add_message (const wstring& app_name, const wstring& message, int font_size_percent, COLORREF font_color) = 0;
   virtual  void clean () = 0;

   
  protected:
               log_view (const log_view& right) {};
   log_view& operator= (const log_view& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
  private:
}; // class log_view

typedef boost::shared_ptr<log_view> ptr_to_log_view;

} // namespace logwnd {
} // namespace gswui {

#endif // _interface_gswui_log_view_h_