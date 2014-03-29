#!/usr/bin/perl -T --  # -*-Perl-*-
use CGI qw/:standard/;
use CGI::Pretty qw(:html3);
use CGI::Carp;
use Socket;
use IO::Handle;
use Net::DNS;
use DBI;
use Digest::SHA1  qw(sha1);
use Sys::Syslog qw(:standard :extended);

#----------------------------------------------------------------------
# Configuration section
#
$sockname =   '/tmp/osap.socket';	# name of Unix socket of osapd.pl
 
#----------------------------------------------------------------------	
#
# Create the main login window
#
sub login_window
{
	my $q = @_[0];
	
	print $q->header, $q->start_html(-title=>'OSAP Login', -style=>{-src=>'/osap/osap.css'});
	
	print $q->h1('Datlan Connexion');
	print $q->start_form;
	print $q->start_table({-width=>'100%'},{-border=>'0'});
	print $q->Tr($q->td({align=>CENTER}, $q->img({src=>'/osap/logo.png'})));
	print $q->end_table, "\n";
	print $q->start_table({-width=>'100%'},{-border=>'0'});
	my $register_widget = $q->table({-border=>'0'},
		$q->Tr($q->td({-colspan=>2, -align=>LEFT}, 
		'Bienvenue sur la page de connexion.<br/>Pour acceder au reseau internet, merci d\'utiliser vos identifiants Datlan :')),
		$q->Tr($q->td({-align=>RIGHT}, 'Utilisateur :'),
			$q->td($q->textfield({-size=>50, name=>'name'}))),
		$q->Tr($q->td({-align=>RIGHT}, 'Mot de passe:'),
			$q->td($q->password_field({-size=>50, name=>'password'}))));
	print $q->Tr($q->td({align=>CENTER}, $register_widget));
	my $read_terms="J'ai lu et j'accepte ";
	my $terms_link=$q->a({-href=>'/osap/terms.html'}, 'les conditions d\'utilisations');
	print $q->Tr($q->td({-colspan=>2, align=>CENTER},
			    $q->checkbox({-name=>'terms', 
					  -class=>'oswap-checkbox',
					  -label=>$read_terms}),
			    $terms_link));
	my $connect_button = $q->table(
		$q->Tr($q->td($q->submit({-name=>OK, -value=>Annuler,
				-class=>'oswap-button-cancel'})),
			$q->td($q->submit({-name=>OK, -value=>Connexion,
				-class=>'oswap-button-ok'}))));
	print $q->Tr($q->td({align=>RIGHT}, $connect_button));
	print $q->end_table, "\n";
	print $q->end_form, "\n";
}

#----------------------------------------------------------------------
# 
# Create the 'session' window, displayed while the connection is active
#
sub session_window {
	my $q = $_[0];
	my $ip = $q->remote_addr;
	my $name = $q->param('name');
	my $email = $q->param('email');
	
	syslog(LOG_INFO, "session: \'$name\', \'$email\', $ip");
	print $q->header, $q->start_html(-title=>'OSAP Login', -style=>{-src=>'/osap/osap.css'});
	
	print $q->h1('Datlan Connexion');
	print $q->start_table({-width=>'100%'},{-border=>'0'});
	print $q->Tr($q->td({align=>CENTER}, $q->img({src=>'/osap/logo.png'})));
	print $q->end_table, "\n";
	print $q->start_form;
	print $q->h3({align=>CENTER}, "Connexion r&eacute;ussie.");
	print $q->p("Une fois que vous souhaiterez vous d&eacute;connecter du r&eacute;seau, vous pouvez cliquer sur le bouton suivant :");
	print $q->start_table({width=>'100%'});
	print $q->Tr({align=>CENTER},
		     $q->td($q->submit({-name=>'OK', -value=>'Deconnexion',
					-class=>'oswap-button-cancel'})));
	print $q->end_table;
	print $q->end_form;
}

#----------------------------------------------------------------------
#
# Create the 'disconnected' screen.
#
sub disconnected_window {
	my $q = $_[0];
	my $myself = $q->self_url;
	
	print $q->header, $q->start_html(-title=>'OSAP Login', -style=>{-src=>'/osap/osap.css'});
	
	print $q->h1('Datlan Connexion');
	print $q->start_table({-width=>'100%'},{-border=>'0'});
	print $q->Tr($q->td({align=>CENTER}, $q->img({src=>'/osap/logo.png'})));
	print $q->end_table, "\n";
	print $q->start_form;
	print $q->h2({align=>CENTER}, "D&eacute;connexion r&eacute;ussie.");
	print $q->p("Merci d'utiliser le r&eacute;seau Datlan.");
	print $q->start_table({width=>'100%'});
	print $q->Tr({align=>CENTER},
		     $q->td($q->submit({-name=>'OK', -value=>'Reconnexion',
					-class=>'oswap-button-ok'})));
	print $q->end_table;
	print $q->end_form;
}

sub login_mysql
{
	my $name = $_[0];
	my $passwd = $_[1];

	$dbh = DBI->connect('DBI:mysql:database=datlan;host=wayt.me', 'gw', 'toto42') || die "Could not connect to database: $DBI::errstr";

	$sql = "SELECT SHA1(?) = use_password FROM t_user WHERE use_username = ?";
	$sth = $dbh->prepare($sql);
 	$sth->execute($passwd, $name) || die "SQL Error: $DBI::errstr\n";

    my ($check) = $sth->fetchrow_array;
    $sth->finish();
	$dbh->disconnect();
    if ($check eq "1") {
        return 1;
    }
    return 0;
}

#----------------------------------------------------------------------
# 
# Validate input in the main login window: 
#
sub validate {
	my $q = $_[0];
	
	my $name = $q->param('name');
	my $pass = $q->param('password');
	my $terms = $q->param('terms');
	my $ip = $q->remote_addr;

	syslog(LOG_DEBUG, "validate \'$name\', \'$pass\', $ip");
	if ($name eq "") {
		return "Merci de renseigner votre nom d'utilisateur.";
	}
	if ($pass eq "") {
		return "Merci de renseigner le mot de passe.";
	}
	if (!defined($terms) || $terms ne 'on') {
		return "Merci de valider les conditions d'utilisations.";
	}
	if (!login_mysql($name, $pass)) {
		return "Mauvaise combinaison Utilisateur/Mot de passe.";
	}
	return "";
}

#----------------------------------------------------------------------
# 
# Send a request to the osapd daemon and wait for the answer
#
sub osapd_client {
	my $cmd = $_[0];
	
	socket(SOCK, PF_UNIX, SOCK_STREAM, 0) || return("socket: $!");
	connect(SOCK, sockaddr_un($sockname)) || return("connect: $!");
	SOCK->autoflush(1);

	print SOCK "$cmd\n" || return("print $!");
	my $result = <SOCK> || return("read $!");
	chop $result;
	print SOCK "QUIT\n" || return("quit $!");

	close SOCK;
	return $result;
}


#----------------------------------------------------------------------
# 
# Add the IP address of the client to the osap clients table in pf
#
sub add_user {
	my $q = $_[0];
	my $ip = $q->remote_addr;
	my $user = $q->param('name');
	$user =~ s/\s+/_/g;
	$user = escapeHTML($user);

	syslog(LOG_DEBUG, "Add $ip $user");
	return osapd_client("ADD $ip $user");
}

#----------------------------------------------------------------------
#
# Remove the IP address of the client from the osap clients table in pf
#
sub del_user {
	my $q = $_[0];
	my $ip = $q->remote_addr;

	syslog(LOG_DEBUG, "Del $ip");
	return osapd_client("DEL $ip");
}

#----------------------------------------------------------------------
#
# Test if the IP address of the client is already authorized
#
sub test_user {
	my $q = $_[0];
	my $ip = $q->remote_addr;

	syslog(LOG_DEBUG, "Test $ip");
	return osapd_client("TST $ip");
}

#----------------------------------------------------------------------  
#
# Main code
#
$q = new CGI;
setlogsock('unix');
openlog('osap', "ndelay,pid", LOG_DAEMON);
$resolver = Net::DNS::Resolver->new;

# print $q->a(href=\"{-noScript=>"terms.htm", -script=>"javascript:popup('terms.html')"\", "Terms");

if ($q->request_method eq "GET") {
	# First time?
	my $user = test_user($q);
	if ($user ne "") {
		$q->param(-name=>'name', -value=>"$user");
		session_window($q);
	} else {
		login_window($q);
	}
} else {
	if ($q->param()) {
		my $which = $q->param('OK');

		if ($which eq "Disconnect") {
			# ignore errors ??
			del_user($q);
			disconnected_window($q);
	 	} elsif ($which eq "Cancel") {
			disconnected_window($q);
		} elsif ($which eq "Reconnect") {
			login_window($q);
		} else {
			my $result = validate($q);
			if ($result ne "") {
				login_window($q);
				print $q->div({class=>'alert'}, $result);
			} else {
				my $pfresult = add_user($q);
				if ($pfresult eq "OK") {
					session_window($q);
				} else {
					# error
					login_window($q);
					print $q->div({class=>'alert'}, 
						      "'$pfresult'");
				}
			}
		}
	}
}
print $q->end_html, "\n";

exit 0;
