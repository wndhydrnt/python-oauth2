Development VM
==============

The development VM helps to quickly set up a dev environment.
It uses VirtualBox and Vagrant to create the virtual machine.
The VM uses the ``precise64`` image provided by Vagrant.
All data is stored in a local mongodb which is installed automatically.

Requirements
------------

- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) to create the VM.
- [Vagrant](http://downloads.vagrantup.com/) to set up the VM.
- [vagrant-omnibus](https://github.com/schisamo/vagrant-omnibus) to keep Chef up-to-date.
- [Bundler](http://bundler.io/) to install gems

Setup
-----

Go into the ``/vagrant`` sub-directory and use vagrant to boot up the VM:

    $ cd ./vagrant
    $ bundle install // install gems. this will install berkshelf.
    $ bundle exec berks vendor ./cookbooks // install chef cookbooks
    $ vagrant up

Creating the VM can take several minutes.

Starting the oauth2 server
------------------------

After the VM has booted up, you can start the oauth2 server:

    $ vagrant ssh
    vagrant@precise64$ python /vagrant/start_provider.py

The server listens on port ``8888``.
You can now start to obtain tokens:

    $ curl "http://127.0.0.1:8888/authorize?response_type=code&client_id=tc&state=xyz" --verbose
