<?php
include("memdb.php");
$m = new memDB();
$m->CreateTable("nisse");
$m->CreateTable("pelle");
$m->AddColumn("nisse", "first", memColInt, 0);
$m->AddColumn("nisse", "second", memColText, "Pelle");
$m->AddRecord("nisse");
$m->SetField("nisse","first",5);
$m->SetFieldByIndex("nisse",1,10);
$m->AddRecord("nisse");
$m->SetField("nisse","first",10);
$m->SetFieldByIndex("nisse",1,"Hej");
echo "<PRE>";
$q = $m->Query("nisse",array("second"=>"==\"Hej\""));
print_r($q);
$t = & $m->GetTable("pelle");
$t->AddColumn("x",memColInt,0);
print_r($m);
$m->Delete("nisse");
print_r($m);
echo "</PRE>";
?>