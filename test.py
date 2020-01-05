from configparser import ConfigParser

cp = ConfigParser()
cp.read('app.conf')

database = cp.get("nginx", "nginx_dirname")
print(database)
