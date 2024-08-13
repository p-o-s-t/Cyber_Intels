// import "pe"

rule rule_name_here : template 
{
    meta: 
  		author = ""
  		description = ""
  		date = "YYYY-MM-DD"
  		version = "1.0"
  		hash = "<MD5|SHA1|SHA256>"
  		score = 0
      reference = "<link>"

    strings:
      $name = "string"
      // $re1 = /^[N].{10,30}[p]$/  // Match first line of chorus
      // $hex1 = { 00 00 FF FF 65 65 }

    condition:
      any of them        
}
