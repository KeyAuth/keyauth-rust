/*!
WARNING! this api version has no special security, it should be only used if you are connecting to keyauth from your server and not from a client.
*/

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use reqwest::blocking::Client;
use reqwest::blocking::Response;
use reqwest::header::{HeaderMap, DATE};
use base16::decode;

/// every function in this struct (accept log) returns a Result and Err("Request was tampered with") will be returned if the request signature doesnt mathc the sha256 hmac of the message
pub struct KeyauthApi {
    name: String,
    owner_id: String,
    #[allow(dead_code)]
    secret: String,
    version: String,
    session_id: String,
    pub api_url: String,
    pub num_keys: String,
    pub num_online_users: String,
    pub num_users: String,
    pub app_version: String,
    pub customer_panel_link: String,
    pub username: String,
    pub ip: String,
    pub hwid: String,
    pub create_date: String,
    pub last_login: String,
    pub subscription: String,
    pub message: String,
    pub success: bool,
    pub blacklisted: bool,
    pub response: String,
    pub time_check_enabled: bool,
    pub max_time_drift_secs: u64,
    server_time_utc: RefCell<Option<SystemTime>>,
    local_time_at_server_time: RefCell<Option<SystemTime>>,
}

impl KeyauthApi {
    /// creats a new KeyauthApi and its defaults, api_url has to be api version 1.2 example: "https://keyauth.win/api/1.2/" or if you have a custom api domain: "https://api.example.com/1.2/"
    pub fn new(name: &str, owner_id: &str, secret: &str, version: &str, api_url: &str) -> Self {
        Self {
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            secret: secret.to_string(),
            version: version.to_string(),
            session_id: String::new(),
            num_keys: String::new(),
            api_url: api_url.to_string(),
            num_online_users: String::new(),
            num_users: String::new(),
            app_version: version.to_string(),
            customer_panel_link: String::new(),
            username: String::new(),
            ip: String::new(),
            hwid: machine_uuid::get(),
            create_date: String::new(),
            last_login: String::new(),
            subscription: String::new(),
            message: String::new(),
            success: false,
            blacklisted: false,
            response: String::new(),
            time_check_enabled: true,
            max_time_drift_secs: 300,
            server_time_utc: RefCell::new(None),
            local_time_at_server_time: RefCell::new(None),
        }
    }

    /// initializes a session, **required to run before any other function in this struct!!!** accept new
    pub fn init(&mut self, hash: Option<&str>) -> Result<(), String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "init");
        if let Some(hash) = hash {
            req_data.insert("hash", hash);
        }
        req_data.insert("ver", &self.version);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        if resp == "KeyAuth_Invalid" {
            return Err("The application doesn't exist".to_string());
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            self.session_id = json_rep["sessionid"].as_str().unwrap().to_string();
            self.num_keys = json_rep["appinfo"]["numKeys"].as_str().unwrap().to_string();
            self.num_online_users = json_rep["appinfo"]["numOnlineUsers"].as_str().unwrap().to_string();
            self.num_users = json_rep["appinfo"]["numUsers"].as_str().unwrap().to_string();
            self.customer_panel_link = json_rep["appinfo"]["customerPanelLink"].as_str().unwrap_or("").to_string();
            Ok(())
        } else {
            if json_rep["message"].as_str().unwrap() == "invalidver" {
                let download_url = json_rep["download"].as_str().unwrap();
                if !download_url.is_empty() {
                    webbrowser::open(download_url).unwrap();
                }
            }
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// registeres a new user
    pub fn register(&mut self, username: String, password: String, license: String, hwid: Option<String>) -> Result<(), String> {
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };
        let mut req_data = HashMap::new();
        req_data.insert("type", "register");
        req_data.insert("username", &username);
        req_data.insert("pass", &password);
        req_data.insert("key", &license);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);
        req_data.insert("hwid", &hwidd);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            self.username = username;
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// upgrades a user license level or extends a license
    pub fn upgrade(&mut self, username: String, license: String) -> Result<(), String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "upgrade");
        req_data.insert("username", &username);
        req_data.insert("key", &license);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// login self explanatory
    pub fn login(&mut self, username: String, password: String, hwid: Option<String>) -> Result<(), String> {
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };

        let mut req_data = HashMap::new();
        req_data.insert("type", "login");
        req_data.insert("username", &username);
        req_data.insert("pass", &password);
        req_data.insert("hwid", &hwidd);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.username = username;
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.hwid = hwidd;
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// <https://docs.keyauth.cc/api/license>
    pub fn license(&mut self, license: String, hwid: Option<String>) -> Result<(), String> {
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };

        let mut req_data = HashMap::new();
        req_data.insert("type", "license");
        req_data.insert("key", &license);
        req_data.insert("hwid", &hwidd);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.username = json_rep["info"]["username"].as_str().unwrap().to_string();
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.hwid = hwidd;
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// this will get a global variable (not user) and return it
    pub fn var(&mut self, varid: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "var");
        req_data.insert("varid", &varid);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// downloads a file, and decodes using base16::decode
    pub fn file(&mut self, fileid: String) -> Result<Vec<u8>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "file");
        req_data.insert("fileid", &fileid);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(decode(json_rep["contents"].as_str().unwrap()).unwrap())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// sends a webhook from keyauth's servers so the url isnt exposed
    pub fn webhook(&mut self, webid: String, params: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "webhook");
        req_data.insert("webid", &webid);
        req_data.insert("params", &params);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// checks if the user is blacklisted and sets self.blacklisted acordingly
    pub fn checkblacklist(&mut self) -> Result<(), String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "checkblacklist");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.blacklisted = true;
            Ok(())
        } else {
            self.blacklisted = false;
            Ok(())
        }
    }

    /// checks if the session is still active or if it expired
    pub fn check_session(&mut self) -> Result<bool, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "check");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        Ok(json_rep["success"].as_bool().unwrap())
    }

    /// gets json of online users
    pub fn fetch_online(&mut self) -> Result<serde_json::Value, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "fetchOnline");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["users"].clone())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// gets the arry of messages in a channel
    pub fn get_chat(&mut self, channel: String) -> Result<serde_json::Value, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "chatget");
        req_data.insert("channel", &channel);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["messages"].clone())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// sends a chat message in a channel
    pub fn send_chat_message(&mut self, channel: String, message: String) -> Result<(), String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "chatsend");
        req_data.insert("channel", &channel);
        req_data.insert("message", &message);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// self explanatory
    pub fn ban(&mut self) {
        let mut req_data = HashMap::new();
        req_data.insert("type", "ban");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let _ = self.request(req_data, self.api_url.clone());
    }

    /// sets a user variable to varvalue
    pub fn setvar(&mut self, varname: String, varvalue: String) -> Result<(), String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "setvar");
        req_data.insert("var", &varname);
        req_data.insert("data", &varvalue);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        self.message = json_rep["message"].as_str().unwrap().to_string();
        self.success = json_rep["success"].as_bool().unwrap();
        Ok(())
    }

    /// gets a user variable
    pub fn getvar(&mut self, varname: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "getvar");
        req_data.insert("var", &varname);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["response"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// logs somethink to keyauth
    pub fn log(&mut self, message: String, pcuser: Option<String>) {
        let usr = match pcuser {
            Some(pcuser) => pcuser,
            None => self.username.clone(),
        };

        let mut req_data = HashMap::new();
        req_data.insert("type", "log");
        req_data.insert("message", &message);
        req_data.insert("pcuser", &usr);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let _ = self.request(req_data, self.api_url.clone());
    }

    /// changes Username, 
    pub fn change_username(&mut self, new_username: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "changeUsername");
        req_data.insert("newUsername", &new_username);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = self.request(req_data, self.api_url.clone())?;
        let _head = req.headers().clone();
        let resp = req.text().unwrap();

        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    fn update_time_from_headers(&self, headers: &HeaderMap) -> Result<(), String> {
        if !self.time_check_enabled {
            return Ok(());
        }
        let date_value = match headers.get(DATE) {
            Some(value) => value,
            None => return Ok(()),
        };
        let date_str = date_value
            .to_str()
            .map_err(|_| "invalid Date header".to_string())?;
        let server_time =
            httpdate::parse_http_date(date_str).map_err(|_| "invalid Date header".to_string())?;
        let now = SystemTime::now();

        let last_local = *self.local_time_at_server_time.borrow();
        if let Some(last_local) = last_local {
            if now.duration_since(last_local).is_err() {
                return Err("system clock moved backwards; possible time tampering".to_string());
            }
        }

        let last_server = *self.server_time_utc.borrow();
        let last_local = *self.local_time_at_server_time.borrow();
        if let (Some(last_server), Some(last_local)) = (last_server, last_local) {
            let elapsed = now
                .duration_since(last_local)
                .unwrap_or(Duration::from_secs(0));
            let expected_server = last_server + elapsed;
            let drift = if server_time >= expected_server {
                server_time
                    .duration_since(expected_server)
                    .unwrap_or(Duration::from_secs(0))
            } else {
                expected_server
                    .duration_since(server_time)
                    .unwrap_or(Duration::from_secs(0))
            };
            if drift.as_secs() > self.max_time_drift_secs {
                return Err(
                    "system clock is out of sync with server time; possible time tampering"
                        .to_string(),
                );
            }
        }

        *self.server_time_utc.borrow_mut() = Some(server_time);
        *self.local_time_at_server_time.borrow_mut() = Some(now);
        Ok(())
    }

    fn request(&self, req_data: HashMap<&str, &str>, url: String) -> Result<Response, String> {
        let client = Client::new();
        let mut req_data_str = String::new();
        for d in req_data {
            req_data_str.push_str(&format!("{}={}&", d.0, d.1))
        }
        req_data_str = req_data_str.strip_suffix("&").unwrap().to_string();
        let resp = client.post(url)
            .body(req_data_str)
            .header("User-Agent", "KeyAuth")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .map_err(|err| err.to_string())?;
        self.update_time_from_headers(resp.headers())?;
        Ok(resp)
    }
}
