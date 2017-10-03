import dropbox

def file_list(oauth2_access_token):

  class File(object):
    def __init__(self, **kwargs):
      for key, value in kwargs.items():
        setattr(self, key, value)

  dbx = dropbox.Dropbox(oauth2_access_token)
  result = []
  for entry in dbx.files_list_folder('').entries:
    f = File(name = entry.name,)
    result.append(f)
  return result

def download_file(oauth2_access_token, filename):
  dbx = dropbox.Dropbox(oauth2_access_token)
  r = dbx.files_download(filename)
  return r

def upload_file(oauth2_access_token, filename, upload):
  dbx = dropbox.Dropbox(oauth2_access_token)
  dbx.files_upload(upload.read(), '/%s' % filename)
