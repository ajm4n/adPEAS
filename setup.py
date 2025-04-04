from setuptools import setup
from distutils.util import convert_path

setup(name='adPEAS',
      version="1.1.0",
      description='winPEAS, but for Active Directory',
      url='https://github.com/ajm4n/adPEAS',
      author='AJ Hammond',
      author_email='aj.hammond@praetorian.com',
      license='MIT',
      packages=['adPEAS'],
      install_requires=[
          'certipy-ad>=4.8.2',
          'bloodhound>=1.7.2',
          'impacket',
          'ldap3==2.9.1',
          'importlib-metadata >= 1.0 ; python_version < "3.8"',
          'regex==2023.12.25',
          'certi @ git+https://github.com/zer1t0/certi@main',
          'NetExec @ git+https://github.com/Pennyw0rth/NetExec@main',
          'termcolor==2.5.0',
          'beautifulsoup4'
      ],
      entry_points={
        'console_scripts': ['adPEAS=adPEAS.command_line:main']
      },
      zip_safe=False)
