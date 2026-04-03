<?php

//======================================================//
//    MySpace Resource Script v1.21 - ScriptHippo.com   //
//======================================================//

//======================================================//
//     This script is created by Script-Hippo for       //
//     use on a single domain. You may not sell,        //
//     copy, distribute, make derivative works or       //
//     otherwise steal this script for any reason.      //
//     If you did not purchase this script directly     //
//     from ScriptHippo.com, you may be entitled to     //
//     a full refund. Please contact ScriptHippo at     //
//     http://www.scripthippo.com/support to report     //
//     this activity.                                   //
//======================================================//

//======================================================//
//             Copyright© ScriptHippo.com               //
//======================================================//

    class page_gen {
        var $_start_time;
        var $_stop_time;
        var $_gen_time;
        var $round_to;
        function page_gen() {
            if (!isset($this->round_to)) {
                $this->round_to = 4;
            }
        }
        function start() {
            $microstart = explode(' ',microtime());
            $this->_start_time = $microstart[0] + $microstart[1];
        }
        function stop() {
            $microstop = explode(' ',microtime());
            $this->_stop_time = $microstop[0] + $microstop[1];
        }
        function gen() {
            $this->_gen_time = round($this->_stop_time - $this->_start_time,$this->round_to);
            return $this->_gen_time; 
        }
    }

$pagegen = new page_gen();
$pagegen->round_to = 5;
$pagegen->start()
?> 