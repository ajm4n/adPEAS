from setuptools import setup

setup(name='adPEAS',
      version='1.0.0',
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