<?php
define("memColUndefined", 0);
define("memColText", 1);
define("memColInt", 2);
define("memColFloat", 3);
define("memColAutoInc", 4);
define("memColCrypt", 16);
define("memSortOrderAsc", 0);
define("memSortOrderDesc", 1);

$sortArray = NULL;
$sortCols = NULL;

function SortCmp($a, $b) {
  global $sortArray;
  global $sortCols;
  if(count($sortArray) > 0) {
    foreach($sortArray as $key => $order) {
	  if(($sortCols[$key][1] == memColInt) | ($sortCols[$key][1] == memColAutoInc) | ($sortCols[$key][1] == memColFloat)) {
	    if($order == memSortOrderAsc) {
	      if($a[$key] > $b[$key]) {
		    return 1;
	      } elseif($a[$key] < $b[$key]) {
		    return -1;
		  }
	    } elseif($order == memSortOrderDesc) {
	      if($a[$key] < $b[$key]) {
		    return 1;
	      } elseif($a[$key] > $b[$key]) {
		    return -1;
		  }
	    } else {
	      return 0;
	    }
	  } elseif($sortCols[$key][1] == memColText) {
	    $strcmp = strcmp($a[$key], $b[$key]);
		if($strcmp != 0) {
		  if($order == memSortOrderAsc) {
		    return $strcmp;
		  } elseif($order == memSortOrderDesc) {
		    return $strcmp * (-1);
		  } else {
		    return 0;
		  }
		  return $strcmp;
		}
	  }
    }
  }
  return 0;
}

$selectFilter = NULL;
$selectCols = NULL;
function selectFilter($var) {
  global $selectFilter;
  global $selectCols;

  if(count($selectFilter) > 0) {
    foreach($selectFilter as $index => $filter) {
	  $value = $var[$index];
	  if(!preg_match("|".$filter."|Ui",$value,$match)) {
	    return false;
	  }
	}
	return true;
  }
  return false;
}
    
// BTNCrypt - Better Than Nothing Crypt
function BTNCrypt($text, $key) {
  $key = md5($key);
  $result = "";
  for($i = 0; $i < strlen($text); $i += strlen($key)) {
    $block = substr($text, $i, strlen($key));
    $crypt = str_pad(" ", strlen($block), " ");
    for($j = 0; $j < strlen($block); $j++) {
      $crypt[$j] = $block[$j] ^ $key[$j];
    }
    $result .= $crypt;
    $key = md5($crypt);
  }
  return base64_encode($result);
}

// BTNDecrypt - Better Than Nothing Decrypt
function BTNDecrypt($text, $key) {
  $text = base64_decode($text);
  $key = md5($key);
  $result = "";
  for($i = 0; $i < strlen($text); $i += strlen($key)) {
    $block = substr($text, $i, strlen($key));
    $decrypt = str_pad("", strlen($block), " ");
    for($j = 0; $j < strlen($block); $j++) {
      $decrypt[$j] = $block[$j] ^ $key[$j];
    }
    $result .= $decrypt;
    $key = md5($block);
  }
  return $result;
}

class memTable {
  var $tablename;
  var $cols;
  var $rowindex;
  var $records;
  var $cryptKey;
    
  function memTable($tablename) {
    // Register "destructor"
    register_shutdown_function(array(&$this, "finalize"));
    $this->tablename = $tablename;
	$this->cols = array();
	$this->rowindex = false;
	$this->records = array();
    $this->cryptKey = "xxxxx";
  }

  function finalize() {
    unset($this->cols);
	unset($this->records);
  }
  
  function Clear() {
	$this->rowindex = false;
	$this->records = array();
  }
  
  function RecordCount() {
    return count($this->records);
  }
  
  function FieldCount() {
    return count($this->cols);
  }
  
  function IsTablename($tablename) {
    return $this->tablename == $tablename;
  }
  
  function SetCryptKey($key) {
    $this->cryptKey = $key;
  }
  
  function _encrypt($text) {
    if(function_exists("mcrypt_ecb")) {
      return mcrypt_ecb(MCRYPT_3DES, $this->cryptKey, $text, MCRYPT_ENCRYPT);
	} elseif(function_exists("md5")) {
	  return BTNCrypt($text, $this->cryptKey);
	}
	return strrev($text);
  }
  
  function _decrypt($text) {
    if(function_exists("mcrypt_ecb")) {
      return mcrypt_ecb(MCRYPT_3DES, $this->cryptKey, $text, MCRYPT_DECRYPT);
	} elseif(function_exists("md5")) {
	  return BTNDecrypt($text, $this->cryptKey);
	}
	return strrev($text);
  }
  
  function AddColumn($colname, $coltype, $defaultvalue) {
	$colindex = 0;
    if(count($this->cols) > 0) {
	  foreach($this->cols as $index => $col) {
	    if($index > $colindex) {
		  $colindex = $index;
		}
	  }
	  $colindex++;
	}
	$this->cols[$colindex] = array(0=>$colname,1=>$coltype,2=>$defaultvalue);
	return $colindex;
  }

  function Delete() {
    unset($this->records[$this->rowindex]);
	$this->ReIndex();
  }
    
  function ReIndex() {
    $temp = array();
	if(count($this->records) == 0) {
	  return;
	}
	foreach($this->records as $index => $record) {
	  $temp[] = $record;
	}
	unset($this->records);
	$this->records = $temp;
	$this->rowindex = 0;
  }
  
  function First() {
	if(count($this->records) > 0) {
	  reset($this->records);
	  $this->rowindex = key($this->records);
	  return true;
	} else {
	  $this->rowindex = false;
	  return false;
	}
  }
  
  function Last() {
	if(count($this->records) > 0) {
	  end($this->records);
	  $this->rowindex = key($this->records);
	  return true;
	} else {
	  $this->rowindex = false;
	  return false;
	}
  }
  
  function Prev() {
	if(count($this->records) > 0) {
	  if(prev($this->records) === false) {
	    reset($this->records);
	    $this->rowindex = key($this->records);
	    return false;
	  } else {
	    $this->rowindex = key($this->records);
	    return true;
	  }
	} else {
	  $this->rowindex = false;
	  return false;
	}
  }
  
  function Next() {
	if(count($this->records) > 0) {
	  if(next($this->records) === false) {
	    end($this->records);
	    $this->rowindex = key($this->records);
	    return false;
	  } else {
	    $this->rowindex = key($this->records);
	    return true;
	  }
	} else {
	  $this->rowindex = false;
	  return false;
	}
  }
  
  function Pos($index) {
    if(isset($this->records[$index])) {
	  reset($this->records);
	  while(key($this->records) !== $index) {
	    if(next($this->records) === false) {
		  break;
		}
	  }
	  return key($this->records) === $index;
	} else {
	  return false;
	}
  }
  
  function AddRecord() {
    $record = array();
	if(count($this->cols) > 0) {
	  foreach($this->cols as $index => $col) {
	    // Check if column is AutoInc. Then AutoInc :-)
	    if($col[1] == memColAutoInc) {
		  $col[2] ++;
		  $this->cols[$index][2]++;
		}
	    $record[$index] = $col[2];
	  }
	}
    $this->records[] = $record;
	end($this->records);
	$this->rowindex = intval(key($this->records));
  }

  function AddRecordWithValue($fields) {
    $this->AddRecord();
	if(count($fields)) {
	  foreach($fields as $key => $value) {
	    $this->SetField($key, $value);
	  }
	}
  }
    
  function AddRecordWithValueByIndex($fields) {
    $this->AddRecord();
	if(count($fields)) {
	  foreach($fields as $key => $value) {
	    $this->SetFieldByIndex($key, $value);
	  }
	}
  }
    
  function GetFieldIndex($fieldname) {
    foreach($this->cols as $index => $col) {
	  if($col[0] === $fieldname) {
	    return $index;
	  }
	}
	return false;
  }
  
  function GetField($fieldname) {
    foreach($this->cols as $index => $col) {
	  if($col[0] === $fieldname) {
	    if($col[1] == memColCrypt) {
	      return $this->_decrypt($this->records[$this->rowindex][$index]);
		} else {
	      return $this->records[$this->rowindex][$index];
		}
	  }
	}
	return false;
  }
  
  function GetFieldByIndex($fieldindex) {
	if($this->cols[$fieldindex][1] == memColCrypt) {
      return $this->_decrypt($this->records[$this->rowindex][intval($fieldindex)]);
	} else {
      return $this->records[$this->rowindex][intval($fieldindex)];
	}
  }

  function SetField($fieldname, $value) {
    foreach($this->cols as $index => $col) {
	  if($col[0] === $fieldname) {
	    if($col[1] == memColCrypt) {
	      return ($this->records[$this->rowindex][intval($index)] = $this->_encrypt($value));
		} else {
	      return ($this->records[$this->rowindex][intval($index)] = $value);
		}
	  }
	}
	return false;
  }
  
  function SetFieldByIndex($fieldindex, $value) {
	if($this->cols[$fieldindex][1] == memColCrypt) {
      return ($this->records[$this->rowindex][intval($fieldindex)] = $this->_encrypt($value));
	} else {
      return ($this->records[$this->rowindex][intval($fieldindex)] = $value);
	}
  }

  function GetRow() {
    return serialize($this->records[$this->rowindex]);
  }
  
  function SetRow($rowdata) {
    $this->records[$this->rowindex] = unserialize($rowdata);
  }
  
  function GetFieldInfo($fieldname) {
    foreach($this->cols as $index => $col) {
	  if($col[0] === $fieldname) {
	    return $col;
	  }
	}
	return false;
  }
  
  function GetFieldInfoByIndex($fieldindex) {
    return $this->cols[$fieldindex];
  }

  function importCSV($csv, $delimiter, $preserveOld = true) {
    if($preserveOld === false) {
	  $this->Clear();
	}
	$lines = explode("\n",$csv);
	foreach($lines as $row) {
	  $cols = split(preg_quote($delimiter),$row);
	  $this->AddRecord();
	  foreach($cols as $index => $col) {
	    $value = "";
		if($this->cols[$index][1] == memColInt) {
		  $value = intval($col);
		} elseif($this->cols[$index][1] == memColFloat) {
		  $value = doubleval($col);
		} elseif($this->cols[$index][1] == memColCrypt) {
		  // Handle info to decrypt
		} elseif($this->cols[$index][1] == memColText) {
		  $value = trim($col);
		  if(strpos($value,"\"") === 0) {
		    if(preg_match("/^([\"\'])(.*)(\\1)$/U",$value,$match)) {
			  $value = $match[1];
			}
		  }
		}
		$this->SetFieldByIndex($index,$value);
	  }
	}
  }
  
  function exportCSV($delimiter, $quotechar = "\"") {
    $return = "";
    if(count($this->records) > 0) {
	  foreach($this->records as $index => $record) {
	    $line = "";
	    if(count($record) > 0) {
		  foreach($record as $index => $col) {
		    if(strlen($line) > 0) {
		      $line .= $delimiter;
		    }
			if($this->cols[$index][1] == memColInt) {
			  $line .= $col;
			} elseif($this->cols[$index][1] == memColFloat) {
			  $line .= $col;
		    } elseif($this->cols[$index][1] == memColCrypt) {
			  // Handle info to encrypt
			} elseif($this->cols[$index][1] == memColText) {
			  $line .= $quotechar.$col.$quotechar;
			}
		  }
		}
		$return .= $line."\n";
	  }
	}
	return $return;
  }

  function SortByIndex($sortorder) {
    global $sortArray;
	global $sortCols;
	
	$sortArray = $sortorder;
	$sortCols = $this->cols;
    usort(&$this->records,"SortCmp");
	$this->ReIndex();
  }
  
  function Sort($sortorder) {
    global $sortArray;
	global $sortCols;
	
	$newsortorder = array();
	if(count($sortorder) > 0) {
	  foreach($sortorder as $key => $value) {
	    $newsortorder[$this->GetFieldIndex($key)] = $value;
	  }
	}
	$sortArray = $newsortorder;
	$sortCols = $this->cols;
    usort(&$this->records,"SortCmp");
	$this->ReIndex();
  }

  function Select($select) {
    global $selectFilter;
	global $selectCols;
	
	$newSelectFilter = array();
	if(count($select) > 0) {
	  foreach($select as $key => $value) {
	    $newSelectFilter[$this->GetFieldIndex($key)] = $value;
	  }
	}
	$selectFilter = $newSelect;
	$selectCols = $this->cols;
	$select = array_filter($this->records,"selectFilter");
	$selectQuery = new memQuery($this->tablename);
	$selectQuery->records = $select;
	$selectQuery->cols = $this->cols;
	$selectQuery->ReIndex();
	return $selectQuery;
  }
    
  function SelectByIndex($select) {
    global $selectFilter;
	global $selectCols;
	
	$selectFilter = $select;
	$selectCols = $this->cols;
	$select = array_filter($this->records,"selectFilter");
	$selectQuery = new memQuery($this->tablename);
	$selectQuery->records = $select;
	$selectQuery->cols = $this->cols;
	$selectQuery->ReIndex();
	return $selectQuery;
  }
    
}

class memQuery extends memTable {
}

class memDB {
  var $tables;
  
  function memDB() {
    // Register "destructor"
    register_shutdown_function(array(&$this, "finalize"));
    $this->tables = array();
  }
  
  function finalize() {
	unset($this->tables);
  }
  
  function _encrypt($key, $text) {
    if(function_exists("mcrypt_ecb")) {
      return mcrypt_ecb(MCRYPT_3DES, $key, $text, MCRYPT_ENCRYPT);
	} elseif(function_exists("md5")) {
	  return BTNCrypt($text, $key);
	}
	return strrev($text);
  }
  
  function _decrypt($key, $text) {
    if(function_exists("mcrypt_ecb")) {
      return mcrypt_ecb(MCRYPT_3DES, $key, $text, MCRYPT_DECRYPT);
	} elseif(function_exists("md5")) {
	  return BTNDecrypt($text, $key);
	}
	return strrev($text);
  }
  
  function LoadDatabase($s, $filename = "",$key = "") {
    if(strlen($filename) > 0) {
	  if(file_exists($filename)) {
	    $s = file_get_contents($filename);
	  }
	}
    if(strpos($s,"BTN")===0) {
	  if(function_exists("md5")) {
	    $s = BTNDecrypt(substr($s,3,strlen($s)),$key);
	  } else {
	    // String is encrypted with BTN and there is no decryption function available
	  }
	}
    if(strpos($s,"_CR")===0) {
	  $s = $this->_decrypt($key,substr($s,3,strlen($s)));
	}
    if(strpos($s,"BZ")===0) {
	  if(function_exists("bzdecompress")) {
	    $s = bzdecompress($s);
	  } else {
	    // String is packed with BZ2 and there is no decompression function available
	  }
	}
	$this = unserialize($s);
  }
  
  function SaveDatabase($filename = "") {
    // Hide password when saving
	$object = preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this));
    if(strlen($filename) > 0) {
	  $fp = fopen($filename, "w+");
//	  fwrite($fp, serialize($this));
	  fwrite($fp, $object);
	  fclose($fp);
	} else {
//      return serialize($this);
      return $object;
	}
  }
  
  function SaveDatabaseBZ2($filename = "") {
    // Hide password and compress when saving
	if(function_exists("bzcompress")) {
	  $object = bzcompress(preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this)));
	} else {
	  // The same as $this->SaveDatabase($filename);
	  $object = preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this));
	}
    if(strlen($filename) > 0) {
	  $fp = fopen($filename, "w+");
//	  fwrite($fp, serialize($this));
	  fwrite($fp, $object);
	  fclose($fp);
	} else {
//      return serialize($this);
      return $object;
	}
  }
  
  function SaveDatabaseBTN($key, $filename = "") {
    // Hide password and compress when saving
	if(function_exists("md5")) {
	  $object = "BTN".BTNCrypt(preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this)),$key);
	} else {
	  // The same as $this->SaveDatabase($filename);
	  $object = preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this));
	}
    if(strlen($filename) > 0) {
	  $fp = fopen($filename, "w+");
//	  fwrite($fp, serialize($this));
	  fwrite($fp, $object);
	  fclose($fp);
	} else {
//      return serialize($this);
      return $object;
	}
  }
  
  function SaveDatabaseBZ2BTN($key, $filename = "") {
    // Hide password and compress when saving
	if(function_exists("bzcompress")) {
	  $object = bzcompress(preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this)));
	} else {
	  // The same as $this->SaveDatabase($filename);
	  $object = preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this));
	}
	if(function_exists("md5")) {
	  $object = "BTN".BTNCrypt($object,$key);
	}
    if(strlen($filename) > 0) {
	  $fp = fopen($filename, "w+");
//	  fwrite($fp, serialize($this));
	  fwrite($fp, $object);
	  fclose($fp);
	} else {
//      return serialize($this);
      return $object;
	}
  }
  
  function SaveDatabaseCR($key, $filename = "") {
    // Hide password and compress when saving
	$object = "_CR".$this->_encrypt($key,preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this)));
    if(strlen($filename) > 0) {
	  $fp = fopen($filename, "w+");
//	  fwrite($fp, serialize($this));
	  fwrite($fp, $object);
	  fclose($fp);
	} else {
//      return serialize($this);
      return $object;
	}
  }
  
  function SaveDatabaseBZ2CR($key, $filename = "") {
    // Hide password and compress when saving
	if(function_exists("bzcompress")) {
	  $object = bzcompress(preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this)));
	} else {
	  // The same as $this->SaveDatabase($filename);
	  $object = preg_replace("|\"cryptKey\";s\:.*\:\".*\";|Ui","\"cryptKey\";s:5:\"?????\";",serialize($this));
	}
	$object = "_CR".$this->_encrypt($key,$object);
    if(strlen($filename) > 0) {
	  $fp = fopen($filename, "w+");
//	  fwrite($fp, serialize($this));
	  fwrite($fp, $object);
	  fclose($fp);
	} else {
//      return serialize($this);
      return $object;
	}
  }
  
  function CreateTable($tablename) {
    $this->tables[] = new memTable($tablename);
  }
  
  function Clear($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->Clear();
	}
	return false;
  }
  
  function RecordCount($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->RecordCount();
	}
	return false;
  }
  
  function FieldCount($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->FieldCount();
	}
	return false;
  }
  
  function SetCryptKey($tablename, $key) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->SetCryptKey($key);
	}
	return false;
  }
  
  function AddColumn($tablename, $colname, $coltype, $defaultvalue) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->AddColumn($colname, $coltype, $defaultvalue);
	}
	return false;
  }
  
  function Delete($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->Delete();
	}
	return false;
  }
  
  function GetTableIndex($tablename) {
    foreach($this->tables as $index => $table) {
	  if($table->IsTablename($tablename)) {
	    return $index;
	  }
	}
	return NULL;
  }

  function First($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->First();
	}
	return false;
  }
    
  function Last($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->Last();
	}
	return false;
  }
    
  function Prev($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->Prev();
	}
	return false;
  }
    
  function Next($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->Next();
	}
	return false;
  }
    
  function Pos($tablename,$index) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->Pos($index);
	}
	return false;
  }

  function AddRecord($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->AddRecord();
	}
	return false;
  }

  function AddRecordWithValue($tablename, $fields) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->AddRecordWithValue($fields);
	}
	return false;
  }
  
  function AddRecordWithValueByIndex($tablename, $fields) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->AddRecordWithValueByIndex($fields);
	}
	return false;
  }
  
  function GetField($tablename, $fieldname) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->GetField($fieldname);
	}
	return false;
  }
  
  function GetFieldByIndex($tablename, $fieldindex) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->GetFieldByIndex($fieldindex);
	}
	return false;
  }
  
  function SetField($tablename, $fieldname, $value) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->SetField($fieldname, $value);
	}
	return false;
  }
  
  function SetFieldByIndex($tablename, $fieldindex, $value) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->SetFieldByIndex($fieldindex, $value);
	}
	return false;
  }
  
  function GetFieldInfo($tablename, $fieldname) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->GetFieldInfo($fieldname);
	}
	return false;
  }
  
  function GetFieldInfoByIndex($tablename, $fieldindex) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->GetFieldInfoByIndex($fieldindex);
	}
	return false;
  }
  
  function importCSV($tablename, $csv, $delimiter, $preserveOld = true) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->importCSV($csv, $delimiter, $preserveOld);
	}
	return false;
  }
  
  function exportCSV($tablename, $delimiter, $quotechar = "\"") {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex]->exportCSV($delimiter, $quotechar);
	}
	return false;
  }
  
  function & Query($tablename, $filter = NULL) {
    $qtable = new memQuery($tablename);
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  if(count($filter) == 0) {
	    $table->cols = $this->tables[$tableindex]->cols;
	  } else {
	    foreach($filter as $fieldname => $s) {
		  $qtable->cols[] = $this->tables[$tableindex]->cols[$this->tables[$tableindex]->GetFieldIndex($fieldname)];
		}
	  }
	  if($this->tables[$tableindex]->First()) {
	    do {
		  if(is_array($filter)) {
		    if(count($filter) == 0) {
		      $qtable->AddRecord();
		      $qtable->SetRow($this->tables[$tableindex]->GetRow());
			} else {
			  // Check if record matches filter
			  $valid = true;
			  foreach($filter as $field => $s) {
			    $fieldindex = $this->tables[$tableindex]->GetFieldIndex($field);
				$value = $this->tables[$tableindex]->GetFieldByIndex($fieldindex);
		        if($this->tables[$tableindex]->cols[$fieldindex][1] == memColInt) {
		          $value = intval($value);
		        } elseif($this->tables[$tableindex]->cols[$fieldindex][1] == memColFloat) {
		          $value = doubleval($value);
		        } elseif($this->tables[$tableindex]->cols[$fieldindex][1] == memColText) {
		          $value = trim($value);
	              if(preg_match("/^([\"\'])(.*)(\\1)$/U",$value,$match)) {
			        $value = "\"".$match[1]."\"";
			      } else {
					$value = "\"".$value."\"";
				  }
		        }
				eval("\$valid &= (".$value.$s.");");
				if($valid === false) {
				  break;
				}
			  }
			  if($valid == true) {
		        $qtable->AddRecord();
		        $qtable->SetRow($this->tables[$tableindex]->GetRow());
			  }
			}
		  } else {
		    $qtable->AddRecord();
		    $qtable->SetRow($this->tables[$tableindex]->GetRow());
		  }
		} while($this->tables[$tableindex]->Next());
	  }
	}
	$qtable->ReIndex();
	$qtable->First();
	return $qtable;
  }
  
  function GetTable($tablename) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  return $this->tables[$tableindex];
	}
	return false;
  }
  
  function SortByIndex($tablename, $sortorder) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  $this->tables[$tableindex]->SortByIndex($sortorder);
	}
	return false;
  }
  
  function Sort($tablename, $sortorder) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  $table = &$this->tables[$tableindex];
	  $table->Sort($sortorder);
	}
	return false;
  }
  
  function SelectByIndex($tablename, $select) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  $this->tables[$tableindex]->SelectByIndex($select);
	}
	return false;
  }
  
  function Select($tablename, $select) {
    $tableindex = &$this->GetTableIndex($tablename);
	if($tableindex !== false) {
	  $this->tables[$tableindex]->Select($select);
	}
	return false;
  }
  
}
?>