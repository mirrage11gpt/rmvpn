package controlplane

import "testing"

func TestReservableBytesNeverOversubscribes(t *testing.T){cases:=[]struct{remaining,active,request,want int64}{{100,0,30,30},{100,80,30,20},{100,100,1,0},{100,120,1,0},{100,0,-1,0}};for _,c:=range cases{if got:=reservableBytes(c.remaining,c.active,c.request);got!=c.want{t.Fatalf("%+v got %d",c,got)}}}
