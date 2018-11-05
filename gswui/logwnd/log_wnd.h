//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_log_wnd_h__
 #define __gswui_log_wnd_h__

#include "commonlib/commondefs.h"
#include "commonlib/thread.h"

#include "config/configurator.h"

#include "redit_log_view.h"

#include <string>
#include <list>
#include <hash_map>

namespace gswui {
namespace logwnd {

class log_wnd;

//****************************************************************************************//

typedef std::wstring  wstring;

class log_wnd
{
  public:
    enum PaintAlgo
    {
        PaintAlgoFallTo10 = 1,
        PaintAlgoFallTo20,
        PaintAlgoFallTo40,
        PaintAlgoFallTo60,
        PaintAlgoFallTo80
    }; // enum PaintAlgo
    typedef commonlib::sync::SyncObject             sync_object;

  protected:
    enum skin_align_t
    {
        skin_align_top_left,
        skin_align_top_right,
        skin_align_top_center,      // temporary unsupported
        skin_align_bottom_left,     
        skin_align_bottom_right,    
        skin_align_bottom_center,   
        skin_align_left_center,     // temporary unsupported
        skin_align_right_center,    // temporary unsupported
        skin_align_center           // temporary unsupported
    }; // enum skin_align_t
    
    enum skin_shift_t
    {
        skin_shift_percents,
        skin_shift_pixels
    }; // enum skin_shift_t
    
    struct skin_bitmap_t
    {
        skin_bitmap_t (HINSTANCE global_instance, int bitmap_resource_id, skin_align_t align, int shift, skin_shift_t shift_type) 
          : m_bitmap_resource_id (bitmap_resource_id),
            m_skin_bitmap (NULL),
            m_align (align),
            m_shift_type (shift_type),
            m_shift ((skin_shift_pixels == m_shift_type || 200 >= ((unsigned int) shift + 100)) ? shift : 0)
        {
            memset (&m_skin_bitmap_info, 0, sizeof (m_skin_bitmap_info));
            memset (&m_placement, 0, sizeof (m_placement));
            
            if (0 <= m_bitmap_resource_id)
            {
                m_skin_bitmap = ::LoadBitmapW (global_instance, MAKEINTRESOURCE(m_bitmap_resource_id));
                ::GetObjectW (m_skin_bitmap, sizeof (m_skin_bitmap_info), &m_skin_bitmap_info);
            }
        } // skin_bitmap_t
        
        ~skin_bitmap_t ()
        {
            if (NULL != m_skin_bitmap)
                ::DeleteObject (m_skin_bitmap);
            m_skin_bitmap = NULL;    
        } // ~skin_bitmap_t ()
        
        const int           m_bitmap_resource_id;
        const skin_align_t  m_align;
        const skin_shift_t  m_shift_type;
        const int           m_shift;
        HBITMAP             m_skin_bitmap;
        BITMAP              m_skin_bitmap_info;
        
        RECT                m_placement;
    }; // struct skin_bitmap_t
    
    typedef boost::shared_ptr <skin_bitmap_t>         ptr_to_skin_bitmap;
    typedef stdext::hash_map <int, ptr_to_skin_bitmap> skin_bitmap_map;
    
    typedef config::Configurator::PtrToINode        ptr_to_config_node;

  private:
    typedef commonlib::thread                       work_thread;
    typedef boost::shared_ptr <work_thread>         ptr_to_work_thread;
    typedef boost::shared_ptr <wstring>             ptr_to_wstring;
    typedef std::list <ptr_to_wstring>              string_list;
    typedef commonlib::sync::IntrusiveAtomicCounter atomic_counter;
    
    
    struct thread_stub
    {
        thread_stub (log_wnd& func_holder)
            : m_func_holder (func_holder)
        {
        }
        
        void operator()()
        {
            m_func_holder.gui_thread_proc ();
        }    
        
        log_wnd& m_func_holder;
    }; // struct thread_stub
    friend struct thread_stub;

  public:
    explicit 
        log_wnd (
            HINSTANCE       global_instance, 
            const wstring&  name, 
            const wstring&  wnd_name,
            COLORREF        bkg_color,
            int             stable_time,
            int             visible_time,
            int             font_size,
            COLORREF        font_color,
            int             skin_mask_resource_id = -1,
            int             skin_bitmap_resource_id = -1
        );
    virtual ~log_wnd ();

    void      destroy ();
    
    void      add_skin_bitmap (int bitmap_resource_id, skin_align_t align, unsigned int shift_persents = 0, skin_shift_t shift_type = skin_shift_percents);
    void      remove_skin_bitmap (int bitmap_resource_id);
    ptr_to_skin_bitmap get_skin_bitmap_info (int bitmap_resource_id);
    
    void      hide ();
    bool      is_visible ();

    virtual void      add_message (const wstring& app_name, const wstring& message);
    virtual void      clean ();

    //
    PaintAlgo get_paint_algo ();
    void      set_paint_algo (PaintAlgo algo);
    
    int       get_stable_time ();
    void      set_stable_time (int stable_time);
    int       get_visible_time ();
    void      set_visible_time (int visible_time);
    
    COLORREF  get_bkg_color ();
    void      set_bkg_color (COLORREF bkg_color);
    void      select_bkg_color (HWND hwnd);
    
    COLORREF  get_font_color ();
    void      set_font_color (COLORREF font_color);
    
    int       get_font_size (); // percents
    void      set_font_size (int size);
    
    void      set_repaint_timer_resolution (unsigned int resolution); // msec
    
  protected:
    virtual HWND    create_window (DWORD ex_style, DWORD style, const wstring& wnd_name, const wstring& class_name);
    virtual LRESULT wnd_proc (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    
    virtual LRESULT on_rich_edit_notify (HWND hwnd, NMHDR* nm_hdr);
    virtual LRESULT on_command (HWND hwnd, int idCommand, HWND hwndCtl, UINT codeNotify);
    virtual LRESULT on_sys_command (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    
    virtual void    check_reload_setting ();
    virtual void    reload_setting ();
    virtual void    reload_setting (ptr_to_config_node& params);
    
    void      hide_log_window (HWND hwnd);
    ptr_to_config_node get_config_node ();
    
    void      refresh_logwnd ();
    
  private:
    int       gui_thread_proc ();
    
    void      init_skin ();
    void      refresh_region ();
    
    void      create_repaint_timer ();
    void      kill_repaint_timer ();
    
    void      init_log_control (HWND parent_window);

    bool      draw_skin (HWND hwnd);
    void      draw_skin_foreground (HDC destination_dc, const RECT& client_rect);
    void      calc_horizontal_shift (ptr_to_skin_bitmap& info, const RECT& client_rect);
    void      calc_vertical_shift (ptr_to_skin_bitmap& info, const RECT& client_rect);
    void      recalc_skin_params ();
    LRESULT   repaint_log_window (HWND hwnd);
    void      refresh_paint (int paint_algo);
    bool      refresh_paint_algo (PaintAlgo algo);
    void      get_log_window_placement (RECT& result);
    
    void      refresh_window_background (COLORREF color);
    HBRUSH    get_bkg_brush ();
    
    static    LRESULT CALLBACK wnd_callback (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

  public:
  protected:
    const wstring       m_name;
    const wstring       m_wnd_name;
    const unsigned int  m_instance_id;
    
    HINSTANCE           m_global_instance;
    HWND                m_hwnd_log_window;
    
    ptr_to_log_view     m_view_control;

    bool                m_init_complete;
    bool                m_init_result;
    bool                m_need_reload_setting;
    sync_object         m_init_complete_sync;
    ptr_to_work_thread  m_gui_thread;
    
    int                 m_current_alpha;

    UINT_PTR            m_repaint_timer_id;
    UINT                m_repaint_timer_resolution; // msec

    COLORREF            m_bkg_color_default;
    COLORREF            m_bkg_color;
    HBRUSH              m_bkg_brush;
    bool                m_refresh_bkg_brush;

    int                 m_stable_time;
    int                 m_visible_time;

    int                 m_font_size_percent;
    COLORREF            m_font_color;

    int                 m_window_size_x;
    int                 m_window_size_y;
    
    int                 m_window_size_x_min;
    int                 m_window_size_y_min;
    int                 m_window_size_x_max;
    int                 m_window_size_y_max;
    
    int                 m_logwnd_prev_height;
    int                 m_list_control_req_height;
    
    int                 m_current_paint_algo;
    
    int                 m_current_stable_time;
    int                 m_current_visible_time;
    int                 m_current_direction;
    
    int                 m_skin_mask_resource_id;
    int                 m_skin_bitmap_resource_id;
    int                 m_skin_top_bitmap_resource_id;
    
    HBITMAP             m_skin_bitmap;
    BITMAP              m_skin_bitmap_info;
    
    HBITMAP             m_skin_mask_bitmap;
    BITMAP              m_skin_mask_bitmap_info;
    
    int                 m_caption_height;
    int                 m_bottom_height;
    skin_bitmap_map     m_skin_bitmaps;
    
    HDC                 m_compatible_hdc_1;
    HDC                 m_compatible_hdc_2;
    
  private:
    static atomic_counter m_instance_counter;
}; // class log_wnd

} // namespace logwnd {
} // namespace gswui {

#endif // __gswui_log_wnd_h__