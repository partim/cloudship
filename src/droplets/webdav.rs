extern crate hyper;
extern crate nickel;

use std::io::{Error, ErrorKind};
use std::ffi::OsString;
use std::fmt::Write;
use std::fs;
use std::fs::{DirEntry};
use std::path::{Path, PathBuf, Component};

use nickel::{Continue, Nickel, Request, Response, Middleware,
             MiddlewareResult, Responder};
use nickel::mimes::MediaType;
use nickel::status::StatusCode;


pub struct WebDavHandler {
    root_path: PathBuf,
}
struct DavProp {
    pub creation_date: bool,
    pub display_name: String,
    pub content_length: u32,
    pub content_type: bool,
    pub last_modified: bool,
    pub resource_type: bool,
}

impl DavProp {
    fn new(n: String) -> DavProp {
        DavProp {
            creation_date: false,
            display_name: n,
            content_length: 0,
            content_type: false,
            last_modified: false,
            resource_type: false,
        }
    }
}

impl<D> Responder<D> for DavProp {
    fn respond<'a>(self, mut res: Response<'a, D>) -> MiddlewareResult<'a, D> {
        res.set(MediaType::Xml);
        let mut data = String::with_capacity(100);
        data.write_str("<prop>");
        data.write_str("<creationdate/>");
        write!(data, "<displayname>{}</displayname>", self.display_name);
        data.write_str("<getcontentlength/>");
        data.write_str("<getcontenttype/>");
        data.write_str("<resourcetype/>");
        data.write_str("<supportedlock/>");
        data.write_str("</prop>");
        res.send(data)
    }
}

impl<D> Middleware<D> for WebDavHandler {
    fn invoke<'a>(&self, req: &mut Request<D>, res: Response<'a, D>)
                  -> MiddlewareResult<'a, D> {
        match req.origin.method {
            hyper::method::Method::Get => self.with_path(req, res),
            _ => Ok(Continue(res)),
        }
    }
}

impl WebDavHandler {
    fn new<P: AsRef<Path>>(root_path: P) -> WebDavHandler {
        WebDavHandler {
            root_path: root_path.as_ref().to_path_buf(),
        }
    }

    fn with_path<'a, D>(&self, req: &mut Request<D>, res: Response<'a, D>)
                        -> MiddlewareResult<'a, D> {
        let path = self.root_path.join(request_path(req));

        match fs::metadata(path.as_path()) {
            Ok(ref attr) if attr.is_dir() => {
                match list_dir(&path) {
                    Ok(mut props) => {
                        return res.send(props.remove(0))  // Argh! Argh! Argh!!
                    },
                    Err(_) => return res.error(StatusCode::InternalServerError,
                                               "error listing files"),
                }
            }
            Ok(ref attr) if attr.is_file() => return res.send_file(&path),
            _ => {},
        }
        return Ok(Continue(res))
    }
}

pub fn start() {
    let mut server = Nickel::new();
    server.utilize(WebDavHandler::new(Path::new("/tmp")));
    server.listen("127.0.0.1:8888");
}

fn request_path<D>(req: &Request<D>) -> PathBuf {
    sanitize_path(Path::new(req.path_without_query().unwrap_or("/")))
}

fn sanitize_path(path: &Path) -> PathBuf {
    fn extract_component(c: Component) -> Option<&str> {
        match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        }
    }

    path.components()
        .map(extract_component)
        .filter(Option::is_some)
        .map(Option::unwrap)
        .fold(PathBuf::new(), |acc, e| acc.join(Path::new(e)))
}

fn list_dir(path: &Path) -> Result<Vec<DavProp>, Error> {
    let entries = try!(fs::read_dir(path));
    entries.map(|entry| entry.and_then(|e| as_dav_prop(&e)))
           .collect()
}

fn as_dav_prop(entry: &DirEntry) -> Result<DavProp, Error> {
    entry
        .file_name()
        .into_string()
        .map_err(|e| filename_decode_error(e))
        .map(|f| DavProp::new(f))
}

fn filename_decode_error(name: OsString) -> Error {
    Error::new(ErrorKind::InvalidData,
               format!("unable do encode OsString '{}'",
                       name.to_string_lossy()))
}
