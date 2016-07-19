% usbfilter Rule Validation Prolog Engine
% Making sure that there is no conflict between the new rule and existing rules
% NOTE: make sure you respect De Morgan's laws before reading the damn code!
%
% Dec 22, 2015
% root@davejingtian.org
% http://davejingtian.org
% FYI: Xmas is the perfect holiday to write Prolog!

% Proc table
% proc: pid,ppid,pgid,uid,euid,gid,egid,comm
% pro(name, min, max)
% NOTE: CanNOT define constant value with a variable in Prolog!
% max_int(2147483647).
% max_uint(4294967295).
% pro_val_invalid(-1).
pro(pid, 0, 2147483647).
pro(ppid, 0, 2147483647).
pro(pgid, 0, 2147483647).
pro(uid, 0, 4294967295).
pro(euid, 0, 4294967295).
pro(gid, 0, 4294967295).
pro(egid, 0, 4294967295).
% Do NOT care about comm field
% Helper functors for range checking
pro_range_min(X,M) :- pro(X, M, _).
pro_range_max(X,M) :- pro(X, _, M).
pro_in_range(X,W) :-
	pro_range_min(X,Min),
	pro_range_max(X,Max),
	W>=Min,
	W=<Max.
pro_not_in_range(X,W) :-
	W=\=(-1),
	\+pro_in_range(X,W).
pro_all_in_range(X) :-
	[Vpid,Vppid,Vpgid,Vuid,Veuid,Vgid,Vegid]=X,
	\+pro_not_in_range(pid, Vpid),
	\+pro_not_in_range(ppid, Vppid),
	\+pro_not_in_range(pgid, Vpgid),
	\+pro_not_in_range(uid, Vuid),
	\+pro_not_in_range(euid, Veuid),
	\+pro_not_in_range(gid, Vgid),
	\+pro_not_in_range(egid, Vegid).

% Dev table
% dev: busnum,devnum,portnum,devpath,product,manufacturer,serial
% Range checking only works for the first 3 fields
% MAX_U8=255.
% DEV_VAL_INVALID=-1.
dev(busnum, 0, 2147483647).
dev(devnum, 0, 2147483647).
dev(portnum, 0, 255).
dev(ifnum, 0, 32).
% Helper functors
dev_range_min(X,M) :- dev(X, M, _).
dev_range_max(X,M) :- dev(X, _, M).
dev_in_range(X,W) :-
	dev_range_min(X,Min),
	dev_range_max(X,Max),
	W>=Min,
	W=<Max.
dev_not_in_range(X,W) :-
	W=\=(-1),
	\+dev_in_range(X,W).
dev_all_in_range(X) :-
	[Vbusnum,Vdevnum,Vportnum,Vifnum]=X,
	\+dev_not_in_range(busnum, Vbusnum),
	\+dev_not_in_range(devnum, Vdevnum),
	\+dev_not_in_range(portnum, Vportnum),
	\+dev_not_in_range(ifnum, Vifnum).

% Pkt table
% pkt: type,direction,endpoint,address
% USBFILTER_TYPE_ISO=0.
% USBFILTER_TYPE_INT=1.
% USBFILTER_TYPE_CTRL=2.
% USBFILTER_TYPE_BULK=3.
% USBFILTER_DIR_OUT=0.
% USBFILTER_DIR_IN=1.
% PKT_VAL_INVALID=-1.
% MAX_TYPE=3.
% MAX_DIR=1.
% MAX_4BITS=15.
% MAX_7BITS=127.
pkt(type, 0, 3).
pkt(direction, 0, 1).
pkt(endpoint, 0, 15).
pkt(address, 0, 127).
% Helper functors
pkt_range_min(X,M) :- pkt(X, M, _).
pkt_range_max(X,M) :- pkt(X, _, M).
pkt_in_range(X,W) :-
	pkt_range_min(X,Min),
	pkt_range_max(X,Max),
	W>=Min,
	W=<Max.
pkt_not_in_range(X,W) :-
	W=\=(-1),
	\+pkt_in_range(X,W).
pkt_all_in_range(X) :-
	[Vtype,Vdir,Vend,Vaddr]=X,
	\+pkt_not_in_range(type, Vtype),
	\+pkt_not_in_range(direction, Vdir),
	\+pkt_not_in_range(endpoint, Vend),
	\+pkt_not_in_range(address, Vaddr).

% Lum table
% lum: name
% Ignore the name

% Value predicate
value_all_in_range(ProV,DevV,PktV) :-
	pro_all_in_range(ProV),
	dev_all_in_range(DevV),
	pkt_all_in_range(PktV).

% Behavior
% behavior,action: allow|drop
% USBFILTER_ACT_ALLOW=0.
% USBFILTER_ACT_DROP=1.

% Rule predicate
% USBFILTER_VAL_INVALID=-1.
% USBFILTER_STR_INVALID=na.
:- dynamic(usbfilter_rule/11).
% usbfilter_rule(name,proc_value,proc_name,dev_value,dev_devpath,dev_product,dev_manufacturer,dev_serial,pkt_value,lum_name,behavior).
% Default rules
% NOTE: all fields should be in lower case before passed from usbtables!
usbfilter_rule(kernel1,[-1,-1,0,-1,-1,-1,-1],na,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(kernel2,[-1,-1,1,-1,-1,-1,-1],na,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system1,[-1,-1,-1,-1,-1,-1,-1],init,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system2,[-1,-1,-1,-1,-1,-1,-1],systemd-udevd,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system3,[-1,-1,-1,-1,-1,-1,-1],udisks-part-id,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system4,[-1,-1,-1,-1,-1,-1,-1],mount,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system5,[-1,-1,-1,-1,-1,-1,-1],gvfsd-trash,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system6,[-1,-1,-1,-1,-1,-1,-1],pool,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system7,[-1,-1,-1,-1,-1,-1,-1],v4l_id,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system8,[-1,-1,-1,-1,-1,-1,-1],pulseaudio,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).
usbfilter_rule(system9,[-1,-1,-1,-1,-1,-1,-1],alsa-source-usb,[-1,-1,-1,-1],na,na,na,na,[-1,-1,-1,-1],na,0).

% Subset predicate
not_subset_val(Vs,Vt) :-
	Vt=\=(-1),
	Vs=\=Vt.
subset_val(Vs,Vt) :-
	\+not_subset_val(Vs,Vt).
subset_list([],[]) :- true.
subset_list([Hs|Ts],[Ht|Tt]) :-
	subset_val(Hs,Ht),
	subset_list(Ts,Tt).
not_subset_str(S,T) :-
	T\=na,
	S\=T.
subset_str(S,T) :-
	\+not_subset_str(S,T).

% Conflict helplers
general_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,M1,T1,M2,T2,T3,T4,T5,M3,T6) :-
	subset_list(L1,M1),
	subset_str(S1,T1),
	subset_list(L2,M2),
	subset_str(S2,T2),
	subset_str(S3,T3),
	subset_str(S4,T4),
	subset_str(S5,T5),
	subset_list(L3,M3),
	subset_str(S6,T6).
weak_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,H) :-
	usbfilter_rule(H,M1,T1,M2,T2,T3,T4,T5,M3,T6,A),
	general_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,M1,T1,M2,T2,T3,T4,T5,M3,T6),
	A==B.
strong_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,H) :-
        usbfilter_rule(H,M1,T1,M2,T2,T3,T4,T5,M3,T6,A),
        general_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,M1,T1,M2,T2,T3,T4,T5,M3,T6),
        A=\=B.
no_weak_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,[]) :- true.
no_weak_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,[H|T]) :-
	\+weak_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,H),
	no_weak_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,T).
no_strong_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,[]) :- true.
no_strong_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,[H|T]) :-
        \+strong_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,H),
        no_strong_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,T).
no_general_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,[]) :- true.
no_general_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,[H|T]) :-
	usbfilter_rule(H,M1,T1,M2,T2,T3,T4,T5,M3,T6,_),
        \+general_conflict(L1,S1,L2,S2,S3,S4,S5,L3,S6,M1,T1,M2,T2,T3,T4,T5,M3,T6),
        no_general_conflict_for_all(L1,S1,L2,S2,S3,S4,S5,L3,S6,B,T).

% Conflict predicates
conflict_rule_name(N) :-
	findall(X,usbfilter_rule(X,_,_,_,_,_,_,_,_,_,_),M),
	member(N,M).
conflict_rule_value(P1,D,P2) :-
	\+value_all_in_range(P1,D,P2).
conflict_rule_weak(P1,P1str,D,Dstr1,Dstr2,Dstr3,Dstr4,P2,P2str,B) :-
	findall(X,usbfilter_rule(X,_,_,_,_,_,_,_,_,_,_),M),
	\+no_weak_conflict_for_all(P1,P1str,D,Dstr1,Dstr2,Dstr3,Dstr4,P2,P2str,B,M).
conflict_rule_strong(P1,P1str,D,Dstr1,Dstr2,Dstr3,Dstr4,P2,P2str,B) :-
	findall(X,usbfilter_rule(X,_,_,_,_,_,_,_,_,_,_),M),
	\+no_strong_conflict_for_all(P1,P1str,D,Dstr1,Dstr2,Dstr3,Dstr4,P2,P2str,B,M).
conflict_rule_general(P1,P1str,D,Dstr1,Dstr2,Dstr3,Dstr4,P2,P2str,B) :-
        findall(X,usbfilter_rule(X,_,_,_,_,_,_,_,_,_,_),M),
        \+no_general_conflict_for_all(P1,P1str,D,Dstr1,Dstr2,Dstr3,Dstr4,P2,P2str,B,M).

% External APIs for usbtables
% N: name
% L1: process value list
% S1: process name
% L2: device value list
% S2-S5: device devpath,product,manufacturer,serial
% L3: packet value list
% S6: LUM name
% A: action
% Return true if no conflict; otherwise false
no_conflict(N,L1,S1,L2,S2,S3,S4,S5,L3,S6,A) :-
	\+conflict_rule_name(N),
	\+conflict_rule_value(L1,L2,L3),
	\+conflict_rule_general(L1,S1,L2,S2,S3,S4,S5,L3,S6,A).
	
