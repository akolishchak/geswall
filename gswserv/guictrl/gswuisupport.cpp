//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "gswuisupport.h"
#include "configurator.h"
#include "update/update.h"
#include "db/storage.h"
#include "commonlib/thread.h"
#include "license/licensemanager.h"
#include "gswproc.h"

#include <time.h>

namespace gswserv {
namespace guictrl {

using commonlib::sguard::scope_guard;
using commonlib::sguard::make_guard;

using update::UpdateResult;

typedef commonlib::thread              WorkThread;
typedef boost::shared_ptr <WorkThread> PtrToWorkThread;

static GsWuiSupport::GsWuiClientManager /*GsWuiSupport::*/m_manager;
static AuthorityChecker                 /*GsWuiSupport::*/m_authorityChecker;
static int                              /*GsWuiSupport::*/m_timeout = UserWaitSecs*1000;
static GsWuiSupport::SyncObject         /*GsWuiSupport::*/m_update_sync;
static GsWuiSupport::SyncObject         /*GsWuiSupport::*/m_check_update_sync;

static PtrToWorkThread                  m_update_thread;
static UpdateResult                     m_update_result = update::UpdateStopped; // update finished or not started
static time_t                           m_update_time   = 0;

static PtrToWorkThread                  m_check_update_thread;
static UpdateResult                     m_check_update_result = update::UpdateStopped; // update finished or not started
static time_t                           m_check_update_time   = 0;

struct token_finalizer
{
  void operator () (int fake_data)
  {
    ::RevertToSelf ();
  }
}; // token_finalizer

UpdateResult filter_exception ()
{
  UpdateResult result = update::UpdateOtherError;
debugString ((L"\nGsWuiSupport::filter_exception () [0]"));  
  
  try
  {
    throw;
  }
  catch (const update::ServerException&)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): ServerException"));
    result = update::UpdateServerError;
  }
  catch (const update::InvalidLicenseException&)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): InvalidLicenseException"));          
    result = update::UpdateInvalidLicense;
  }
  catch (const update::LicenseExpiredException&)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): LicenseExpiredException"));
    result = update::UpdateLicenseExpired;
  }
  catch (const update::UpgradeAvailableException&)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): UpgradeAvailableException"));
	result = update::UpdateUpgradeAvailable;
  }
  catch (const update::UpdateException& e)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): UpdateException => %s", e.getMessageTextAndCode ()));      
    result = update::UpdateOtherError;
  }
  catch (const license::LicenseException& e)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): LicenseException => %s", e.getMessageTextAndCode ()));      
    result = update::UpdateInvalidLicense;
  }
  catch (const commonlib::Exception& e)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): Exception => %s", e.getMessageTextAndCode ()));
    result = update::UpdateOtherError;
  }
  catch (const std::exception&)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): std::exception"));
    result = update::UpdateOtherError;
  }
  catch (...)
  {
debugString ((L"\nGsWuiSupport::filter_exception (): unknown exception"));
    result = update::UpdateOtherError;
  }
  

debugString ((L"\nGsWuiSupport::filter_exception () [0]"));    
  return result;
} // filter_exception ()

struct update_thread
{
  update_thread (HANDLE client_token, const wstring& authority_hash, HANDLE process_id)
   : m_client_token (NULL),
     m_authority_hash (authority_hash),
     m_process_id (process_id),
     m_result (update::UpdateOtherError)
  {
    //::DuplicateTokenEx (client_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &m_client_token);
    //::DuplicateToken (client_token, SecurityImpersonation, &m_client_token);
    m_client_token = client_token;
  } 
  
  struct thread_finalizer
  {
    thread_finalizer (UpdateResult& result)
     : m_result (result)
    {
    }
    
    void operator () (int)
    {
      GsWuiSupport::Locker locker (m_update_sync);
      m_update_result = m_result;
      time (&m_update_time);
      m_update_thread.reset ();
    }
    
    UpdateResult& m_result;
  };
    
  void operator() ()
  {
debugString ((L"\nGsWuiSupport::update_thread (): start"));
    scope_guard  thread_fin_guard  = make_guard (0, thread_finalizer (m_result));
    scope_guard  token_close_guard = make_guard (m_client_token, &::CloseHandle);
    bool         first_update      = true;
    UpdateResult result;
    
    do
    {
      try
      {
debugString ((L"\nGsWuiSupport::update_thread (): [0]"));
        result = update ();
debugString ((L"\nGsWuiSupport::update_thread (): [1]"));        
      }
      catch (...)
      {
debugString ((L"\nGsWuiSupport::update_thread (): ... exception ..."));
        result = filter_exception ();
      }

      if (true == first_update || (update::UpdateSuccess != result && update::UpdateNotRequired != result))
      {
        m_result     = result;
        first_update = false;
      }  
    }
    while (update::UpdateSuccess == result);
	//
	// notify driver
	//
	GswProc::RefreshResources();
	GswProc::RefreshApplications();
    
  } // operator ()
  
  UpdateResult update ()
  {
debugString ((L"\nGsWuiSupport::update (): [00]"));
    UpdateResult update_result = update::UpdateStopped;
    wstring      last_update;
	int          last_update_number = Storage::GetUpdateVersion ();
    wchar_t      last_update_buffer [65];
	_itow (last_update_number, last_update_buffer, 10);
    last_update.assign (last_update_buffer);
    
	wstring		 db_version;
	int			 db_version_number = Storage::GetDbVersion();
	wchar_t      db_version_buffer [65];
	_itow (db_version_number, db_version_buffer, 10);
    db_version.assign (db_version_buffer);

	license::LicenseManager::LicenseEssentials License;
	license::LicenseManager::LicenseCopy(License);

	HANDLE thread = GetCurrentThread ();
    if (FALSE == SetThreadToken (&thread, m_client_token))
    {
      update_result = update::UpdateOtherError; // other errors
debugString ((L"\nGsWuiSupport::update_thread (): SetThreadToken (%08x) error => %d", m_client_token, GetLastError ()));      
      return update_result;
    }
    
debugString ((L"\nGsWuiSupport::update (): [01]"));    

    //scope_guard rpc_revert_guard = make_guard (rpc_handle, &::RpcRevertToSelfEx);
    scope_guard rpc_revert_guard = make_guard (0, token_finalizer ());
    
    GsWuiSupport::PtrToClient client = m_manager.getClient (GsWuiSupport::ClientId (m_process_id));
    if (NULL != client.get () && 0 == client->compareAuthorityHash (m_authority_hash))
    {
debugString ((L"\nGsWuiSupport::update (): [02]"));

      wstring work_dir;
      wstring key_file;
      
      config::Configurator::PtrToINode srv_node = config::Configurator::getServiceNode ();
      if (NULL != srv_node.get ())
        work_dir = srv_node->getString (L"InstallDir");
      else
        work_dir = L".";
        
      key_file = work_dir;
      key_file.append (L"/public.key");
      
debugString ((L"\nGsWuiSupport::update (): [03]"));
      
debugString ((L"\nGsWuiSupport::update (): [05]"));
      //update::updateDb (last_update, user_info, key_file);
      //wstring update_file_name = update::getDbUpdate (last_update, user_info);
      wstring update_file_name;
	  size_t file_size = update::getDbUpdate (db_version, last_update, License.InstallId, update_file_name);

debugString ((L"\nGsWuiSupport::update (): [06]"));
      
      rpc_revert_guard.free (); // RevertToSelf (); 
      
      if (0 < file_size)
      {
        update::applyDbUpdate (update_file_name, key_file);
        update_result = update::UpdateSuccess; // required
      }
      else
      {
        update_result = update::UpdateNotRequired; // not required
      }  
    } // if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
    else
    {
debugString ((L"\nGsWuiSupport::update_thread (): client authority error"));          
      update_result = update::UpdateOtherError;
    }
    
    return update_result;
  } // update
  
  HANDLE       m_client_token;
  wstring      m_authority_hash;
  HANDLE       m_process_id;
  UpdateResult m_result;
}; // update_thread

struct check_update_thread
{
  check_update_thread (HANDLE client_token, const wstring& authority_hash, HANDLE process_id)
   : m_client_token (NULL),
     m_authority_hash (authority_hash),
     m_process_id (process_id),
     m_result (update::UpdateOtherError)
  {
    //::DuplicateTokenEx (client_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &m_client_token);
    //::DuplicateToken (client_token, SecurityImpersonation, &m_client_token);
    m_client_token = client_token;
  } 
  
  struct thread_finalizer
  {
    thread_finalizer (UpdateResult& result)
     : m_result (result)
    {
    }
    
    void operator () (int)
    {
      GsWuiSupport::Locker locker (m_check_update_sync);
      m_check_update_result = m_result;
      time (&m_check_update_time);
      m_check_update_thread.reset ();
    }
    UpdateResult& m_result;
  };
    
  void operator() ()
  {
    scope_guard thread_fin_guard  = make_guard (0, thread_finalizer (m_result));
    scope_guard token_close_guard = make_guard (m_client_token, &::CloseHandle);

    try
    {
      m_result = check_update ();
    }
    catch (...)
    {
debugString ((L"\nGsWuiSupport::check_update_thread (): ... exception ..."));
      m_result = filter_exception ();
    }
  } // operator()

  UpdateResult check_update ()
  {
    UpdateResult check_result = update::UpdateStopped;

    wstring      last_update;
    int          last_update_number = Storage::GetUpdateVersion ();
    wchar_t      last_update_buffer [65];
    _itow (last_update_number, last_update_buffer, 10);
    last_update.assign (last_update_buffer);
    
	wstring		 db_version;
	int			 db_version_number = Storage::GetDbVersion();
	wchar_t      db_version_buffer [65];
	_itow (db_version_number, db_version_buffer, 10);
    db_version.assign (db_version_buffer);

	HANDLE thread = GetCurrentThread ();
    if (FALSE == SetThreadToken (&thread, m_client_token)) //RevertToSelf ();
    {
      check_result = update::UpdateOtherError; // other errors
debugString ((L"\nGsWuiSupport::check_update_thread (): SetThreadToken (%08x) error => %d", m_client_token, GetLastError ()));      
      return check_result;
    }
    
    scope_guard rpc_revert_guard = make_guard (0, token_finalizer ());
    
    GsWuiSupport::PtrToClient client = m_manager.getClient (GsWuiSupport::ClientId (m_process_id));
    if (NULL != client.get () && 0 == client->compareAuthorityHash (m_authority_hash))
    {
	  license::LicenseManager::LicenseEssentials License;
	  license::LicenseManager::LicenseCopy(License);
	  bool check_update = update::checkDbUpdate (db_version, last_update, License.InstallId); 
        
      rpc_revert_guard.free (); // RevertToSelf (); 
        
      check_result = (true == check_update) ? update::UpdateAppAvailable : update::UpdateNotRequired; // required or not required
    } // if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
    else
    {
debugString ((L"\nGsWuiSupport::check_update_thread (): client authority error"));              
      check_result = update::UpdateOtherError;
    }

    return check_result;
  } // operator ()
  
  HANDLE       m_client_token;
  wstring      m_authority_hash;
  HANDLE       m_process_id;
  UpdateResult m_result;
}; // check_update_thread

//**********************************************************************************************//
//**********************************************************************************************//
//**********************************************************************************************//

bool GsWuiSupport::init ()
{
  config::Configurator::PtrToINode Node = config::Configurator::getUiNode();
  int WaitSecs = Node->getInt(L"UserWaitSecs");
  if ( WaitSecs != 0 ) m_timeout = WaitSecs;
  return true;
} // init


void GsWuiSupport::clear ()
{
  m_manager.unregisterAllClients ();
} // clear

GUIReply GsWuiSupport::queryReply (HANDLE processId, const RequestType type, const wstring& file1, const wstring& file2)
{
  GUIReply result = gurUndefined;

  PtrToClient client = m_manager.getClient (ClientId (processId));
  if (NULL != client.get ())
  {
    GsWuiRequest::PtrToGsWuiRequest request (new GsWuiRequest (processId, type, file1, file2));
    if (NULL != request.get ())
    {
      PtrToGsWuiResponse response = PtrToGsWuiResponse (client->call (request, m_timeout), boost::detail::static_cast_tag ());
      if (NULL != response.get ())
        result = response->getReply ();
    } // if (NULL != request.get ())
  } // if (NULL != client.get ())

  return result;
} // queryReply

void GsWuiSupport::queryAuthorizationObject (HANDLE processId, wstring& objectName)
{
  m_authorityChecker.queryAuthorityObject (processId, objectName);
} // queryAuthorizationObject

bool GsWuiSupport::registerClient (HANDLE processId, HANDLE objectHandle, wstring& authorityHash)
{
  bool result = false;

  if (true == m_authorityChecker.queryAuthorityHash (processId, objectHandle, authorityHash))
  {
    PtrToClient client = PtrToClient (new GsWuiClient (processId, authorityHash));
    try
    {
      m_manager.registerClient (ClientId (processId), client);
      result = true;
    }
    catch (GUICtrlException&)
    {
    }
  } // if (...)

  return result;
} // registerGsWuiClient

GsWuiSupport::PtrToGsWuiRequest GsWuiSupport::waitRequest (HANDLE processId, const wstring& authorityHash)
{
  PtrToGsWuiRequest result;

  PtrToClient client = m_manager.getClient (ClientId (processId));
  if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
  {
    result = PtrToGsWuiRequest (client->waitCall (Client::Const::infiniteTimeout), boost::detail::static_cast_tag ());
  } // if (NULL != client.get ())

  return result;
} // waitGsWuiRequest

void GsWuiSupport::cancelWaitRequest (HANDLE processId, const wstring& authorityHash)
{
  PtrToGsWuiRequest result;

  PtrToClient client = m_manager.getClient (ClientId (processId));
  if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
  {
    client->cancelWait ();
  } // if (NULL != client.get ())
} // cancelWaitRequest

void GsWuiSupport::putReply (HANDLE processId, const wstring& authorityHash, int requestId, const GUIReply& reply)
{
  putResponse (processId, authorityHash, PtrToGsWuiResponse (new GsWuiResponse (requestId, reply)));
} // putReply

void GsWuiSupport::putResponse (HANDLE processId, const wstring& authorityHash, const PtrToGsWuiResponse& response)
{
  PtrToClient client = m_manager.getClient (ClientId (processId));
  if (NULL != response.get () && NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
    client->setReply (response->getParentRequestId (), response);
} // putResponse

int GsWuiSupport::updateDb (HANDLE processId, const wstring& authorityHash)
{
  GsWuiSupport::Locker locker (m_update_sync);
  UpdateResult update_result = update::UpdateStopped;

debugString ((L"\nGsWuiSupport::updateDb (): start, %d", m_update_result));
  
  if (update::UpdateStopped == m_update_result) // start update
  {
    HANDLE client_token;
    if (TRUE == OpenThreadToken (GetCurrentThread (), TOKEN_ALL_ACCESS, TRUE, &client_token))
    {
      scope_guard token_close_guard = make_guard (client_token, &::CloseHandle);
      m_update_thread = PtrToWorkThread (new WorkThread (update_thread (client_token, authorityHash, processId)));
      if (NULL != m_update_thread.get ())
      {
        token_close_guard.release ();
        
        m_update_result = update::UpdatePending; // update pending
        m_update_time   = 0;
      }  
    }
    else
    {
debugString ((L"\nGsWuiSupport::updateDb (): OpenThreadToken ERROR"));
    }
    
    update_result = m_update_result;  
  }
  else // get result
  {
    GsWuiSupport::PtrToClient client = m_manager.getClient (GsWuiSupport::ClientId (processId));
    if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
    {
      update_result = m_update_result;
      
      if (NULL == m_update_thread.get ())
      {
        time_t cur_time;
        time (&cur_time);
        if (60 < difftime (cur_time, m_update_time))
        {
          m_update_result = update::UpdateStopped; // update finished or not started
          update_result   = static_cast <UpdateResult> (updateDb (processId, authorityHash));
        }
      } // if (NULL == m_update_thread.get ())
    } // if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
  } // else // get result
    
debugString ((L"\nGsWuiSupport::updateDb (): end, %d", m_update_result));
  return update_result;
} // getUpdateDbResult

int GsWuiSupport::checkUpdateDb (HANDLE processId, const wstring& authorityHash)
{
  GsWuiSupport::Locker locker (m_check_update_sync);
  UpdateResult check_result = update::UpdateStopped;

debugString ((L"\nGsWuiSupport::checkUpdateDb (): start, %d", m_check_update_result));

  if (update::UpdateStopped == m_check_update_result) // start check
  {
    HANDLE client_token;
    if (TRUE == OpenThreadToken (GetCurrentThread (), TOKEN_ALL_ACCESS, TRUE, &client_token))
    {
      scope_guard token_close_guard = make_guard (client_token, &::CloseHandle);
      m_check_update_thread = PtrToWorkThread (new WorkThread (check_update_thread (client_token, authorityHash, processId)));
      if (NULL != m_check_update_thread.get ())
      {
        token_close_guard.release ();
        
        m_check_update_result = update::UpdatePending; // update pending
        m_check_update_time   = 0;
      }  
    }
    else
    {
debugString ((L"\nGsWuiSupport::checkUpdateDb (): OpenThreadToken ERROR"));    
    }

    check_result = m_check_update_result;
  }
  else // get result
  {
    GsWuiSupport::PtrToClient client = m_manager.getClient (GsWuiSupport::ClientId (processId));
    if (NULL != client.get () && 0 == client->compareAuthorityHash (authorityHash))
    {
      check_result = m_check_update_result;
      
      if (NULL == m_check_update_thread.get ())
      {
        time_t cur_time;
        time (&cur_time);
        if (60 < difftime (cur_time, m_check_update_time))
        {
          m_check_update_result = update::UpdateStopped; // check update finished or not started
          check_result          = static_cast <UpdateResult> (checkUpdateDb (processId, authorityHash));
        }
      }  
    }  
  }
debugString ((L"\nGsWuiSupport::checkUpdateDb (): end, %d", m_check_update_result));
  return check_result;
} // checkUpdateDb

} // namespace guictrl
} // namespace gswserv 

