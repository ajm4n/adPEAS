from setuptools import setup
from distutils.util import convert_path

main_ns = {}
ver_path = convert_path('adPEAS/_version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(name='adPEAS',
      version=main_ns["__version__"],
      description='winPEAS, but for Active Directory',
      url='https://github.com/ajm4n/adPEAS',
      author='AJ Hammond',
      author_email='aj.hammond@praetorian.com',
      license='MIT',
      packages=['adPEAS'],
      install_requires=[
          'certipy-ad==4.8.2',
          'bloodhound==1.7.2',
          'impacket==0.11.0',
          'ldap3==2.9.1'
      ],
      entry_points={
        'console_scripts': ['adPEAS=adPEAS.command_line:main']
      },
      zip_safe=False)