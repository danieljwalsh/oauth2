

/configuration
\p 1234 
\c 40 400 	
.oauth2.baseurl:"http://localhost:1234/";


// schema
.oauth2.provider:([id:`symbol$()]; scope:(); client_id:(); client_secret:(); auth_endpoint:(); token_endpoint:(); userinfo_endpoint:(); revocation_endpoint:());
.oauth2.domains:([domain:`symbol$()]; provider:`symbol$());
.oauth2.state:([state:`symbol$()]; username:`symbol$(); created:`timestamp$(); provider:`symbol$(); access_token:(); refresh_token:(); ok:`boolean$())

// utility
.oauth2.qs:{[dict]
  dict:$[98h=type dict;first dict;dict];
  :"&" sv ("=" sv .h.hu each) each flip (string key dict;{$[10h=type x;x;string x]} each value dict);
  };
.oauth2.getToken:{[user]
  last exec access_token from .oauth2.state where username=user
  };  


k).oauth2.hmb:{x:$[10=@x;x;1_$x];p:{$[#y;y;x]}/'getenv@+`$_:\("HTTP";"NO"),\:"_PROXY";u:.Q.hap@x;t:~(~#*p)||/(*":"\:u 2)like/:{(("."=*x)#"*"),x}'","\:p 1;a:$[t;p:.Q.hap@*p;u]1; (4+*r ss d)_r:(-1!`$,/($[t;p;u]0 2))($y)," ",$[t;x;u 3]," HTTP/1.1",s,(s/:("Connection: close";"Host: ",u 2;"Authorization: Bearer ",z),((0<#a)#,$[t;"Proxy-";""],"Authorization: Basic ",((-c)_.Q.b6@,/64\:'256/:'"i"$0N 3#a,c#0),(c:.q.mod[-#a;3])#"=")),(d:s,s:"\r\n"),""};
	
.oauth2.startLoginFlow:{[username]
  domain:`$last "@"vs string username; 
  info:.oauth2.provider provider:.oauth2.domains[domain;`provider]; 
  param:enlist `response_type`client_id`redirect_uri`scope`access_type`prompt!(`code; info`client_id; .oauth2.baseurl; info`scope; `offline; `consent );
  /param: ([] response_type:1#`code; client_id:enlist info 1; redirect_uri:enlist BASEURL; scope: enlist info 2; access_type:1#`offline; prompt:1#`consent );
  url:{y,"?",.oauth2.qs .DEBUG.PARAM:update state:x from z}[;info`auth_endpoint;param];
  state:`$"\001" sv (raze string 4?`8;string username);
  insert[`.oauth2.state] `state xkey enlist`state`username`created`provider`access_token`refresh_token`ok!(state;username;.z.p;provider;();();0b);
  url state
  };

.oauth2.authenticate:{[state;code]
  state:$[10h=type state;`$state;state];
  code:$[10h=type code;code;string code];
  state_data:`username`provider#.oauth2.state[state];
  
  info:.oauth2.provider state_data`provider;
  postdata:.oauth2.qs enlist`grant_type`redirect_uri`code`client_id`client_secret`scope!(`authorization_code;.oauth2.baseurl; code; info`client_id; info`client_secret; info`scope);

  // exchange the grant token for an access & refresh token 
  result:result0:.j.k .Q.hp[`$":",info[`token_endpoint];"application/x-www-form-urlencoded";postdata];
  
  // request the user profile using the access token
  result:.j.k .oauth2.hmb[`$":",info[`userinfo_endpoint];`GET;result0[`access_token]];
  if[`picture in key result; .debug.picture:result`picture];
  ok:(result`email_verified)&(first state_data[`username])~`$result`email;

  orig:.oauth2.state[state];
  new:cols[.oauth2.state]#@[orig;`state`access_token`refresh_token`ok`created;:;(state;result0`access_token;result0`refresh_token;ok;.z.p)];

  upsert[`.oauth2.state; new];
  ok
  };	
	
.oauth2.refresh:{[state]
  u:.oauth2.state[state];
  p:.oauth2.provider u`provider;
  postdata:.oauth2.qs `refresh_token`client_id`client_secret`grant_type!(u`token; p`client_id; p`client_secret; `refresh_token);
  result0:.j.k .Q.hp[`$":",p`token_endpoint;"application/x-www-form-urlencoded";postdata];
  orig:.oauth2.state[state];
  new:cols[.oauth2.state]#@[orig;`access_token`created;:;(state;result0`access_token;.z.p)];
  }

.oauth2.configure:{[id;handle;scope]
  r:.j.k last "\r\n\r\n" vs raze read0 handle;
  d:distinct {("/" vs x) 2} each r[`web;`auth_uri`token_uri];
  w:.j.k raze {@[.Q.hg;`$":https://",x,"/.well-known/openid-configuration";{""}]} each d;
  insert[`.oauth2.provider]`id xkey enlist`id`scope`client_id`client_secret`auth_endpoint`token_endpoint`userinfo_endpoint`revocation_endpoint!(id;scope; r[`web;`client_id];r[`web;`client_secret];w[`authorization_endpoint];w[`token_endpoint];w[`userinfo_endpoint];w[`revocation_endpoint]);
  id
  };
	

.oauth2.configure[`google;`:kx_client.json;"openid email profile"];
insert[`.oauth2.domains] ([domain:1#`kx.com]; provider:1#`google);
show .oauth2.provider;

.oauth2.i:0;
.z.ph:{
  if["favicon.ico"~first x;:.h.hy[`html]"";];
  
  // no email present, display the Submit button
  if[""~first x;:.h.hy[`html]"<form>email <input type=\"email\" name=\"e\" autofocus><input type=submit value=Submit></form>"];
  d:.h.uh each (!) . "S=&" 0: 1_first x;
  
  // email present start flow
  if[`e in key d;:"HTTP/1.0 302 ok\r\nLocation: ",.oauth2.startLoginFlow[`$d`e],"\r\nConnection: close\r\n\r\n"];
  
  // response from Google, authenticate. 
  .oauth2.authenticate[`$d`state;d`code];
  
  // return users image to the screen
  .h.hy[`html]"<img src=\"", .debug.picture,"\">"
  }
