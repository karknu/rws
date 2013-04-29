
import System.Environment
import qualified Data.ByteString.Lazy as BL
import Data.Binary.Put
import System.Console.GetOpt

import Parser
import SerializePcap

data Flag = Input String | Output String deriving Show

options :: [OptDescr Flag]
options = [
    Option "i"["input"]   (ReqArg Input "FILE")  "Input File name , e.g. example.pkt",
    Option "o" ["output"]  (ReqArg Output "FILE") "Output File name, e.g out.pcap"
  ]

getInput :: [Flag] -> String
getInput [] = error "Specify input file with '-i <file name>'"
getInput (Input i:_) = i
getInput (_:xs) = getInput xs

getOutput :: [Flag] -> String
getOutput [] = error "Specify output file with '-o <file name>'"
getOutput (Output o:_) = o
getOutput (_:xs) = getOutput xs

main :: IO ()
main = do

    args <- getArgs
    let ( actions, _, _ ) = getOpt RequireOrder options args
    let input = getInput actions
    let output = getOutput actions

    pktfile <- readFile input
    let pkts = readPacket pktfile
 
    --sequence_  (map (BL.putStr . runPut . packetWrite) pkts)
    (BL.writeFile output . runPut . pcapWrite) pkts
   -- print pkts
  
