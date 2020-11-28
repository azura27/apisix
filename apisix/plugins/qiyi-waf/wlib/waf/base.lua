local _M = {}

_M.version = "1.3.2"

return _M

--version update log
--1.2.6
--1. if a request hit waf rule and action is "allow", then it will not be transmit to changting eninge whatever waf mode is active, inactive or simulate


--1.2.5
--1. change rule type, 12000-user rule, 13000-system rule. 14000-sqli rule, 15000-xss rule ...
--2. update verify center and enable it
--3. add action alert
--4. add action verifycache
--5，collect reqLen and respLen in logs
--6. fix some bug


--1.2.4
--1. add black white list function
--2. sync bwl in initialization
--3. add ip_match operator
--4. add clinet_ip in log
--5. change logic of proxy passing to changting engine
--6. fix some bug

--version update log
--1.2.2-1.2.3:
		--1, add port in log in order to identify http or https
		--2, add verify center support, add a new action=REDIRECT_VERIFY
		--3, add log sampling feature, allow non-attack log sampling for each business with user-defined sampling rate
