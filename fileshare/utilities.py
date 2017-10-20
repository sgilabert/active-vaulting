import dropbox

def file_list(oauth2_access_token, sort_field='name', reverse=True):

  class File(object):
    def __init__(self, **kwargs):
      for key, value in kwargs.items():
        setattr(self, key, value)

  dbx = dropbox.Dropbox(oauth2_access_token)
  result = []
  for entry in dbx.files_list_folder('').entries:
    f = File(name = entry.name, last_modified=entry.server_modified, size=entry.size)
    result.append(f)
  reverse = str(reverse).lower() in ['true', 't', 'yes', 'y']
  if sort_field == 'name':
    result.sort(key=lambda x: getattr(x, sort_field).lower(), reverse=reverse)
  else:
    result.sort(key=lambda x: getattr(x, sort_field), reverse=reverse)
  return result

def download_file(oauth2_access_token, filename):
  dbx = dropbox.Dropbox(oauth2_access_token)
  r = dbx.files_download(filename)
  return r

def upload_file(oauth2_access_token, filename, upload):
  dbx = dropbox.Dropbox(oauth2_access_token)
  dbx.files_upload(upload.read(), '/%s' % filename)
