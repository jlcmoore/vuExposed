create table requests (
	ts varchar(250),
	source varchar(250),
	dest varchar(250),
	dest_port integer,
	method varchar(250),
	host varchar(250),
	uri varchar(250),
	url varchar(250),
	referrer varchar(250),
	user_agent varchar(250),
	content_length integer,
	basic_auth_user varchar(250),
	trans_depth integer
);

.mode tabs
.import test_requests.tsv requests
.header on
.separator "\t"