use 5.010;
use inc::Module::Install;

name 'CatalystX-OAuth2';
all_from 'lib/CatalystX/OAuth2.pm';
author q{Lenz Gschwendtner <norbu09@cpan.org>};
license 'perl';

build_requires 'Test::More';

requires 'Moose' => '1.03';
requires 'namespace::autoclean';
requires('Catalyst::Runtime' => '5.80030');
requires 'Catalyst::Controller::ActionRole';
requires 'MooseX::SetOnce';

repository 'https://github.com/norbu09/CatalystX-OAuth2';

auto_install;

WriteAll;

