module Lexer (parens, braces, semiSep, semiSep1, commaSep, commaSep1, brackets,
              whiteSpace, symbol, identifier, reserved, reservedOp, integer,
              hexadecimal, float, charLiteral, stringLiteral,
              naturalOrFloat) where

import Text.ParserCombinators.Parsec
import qualified Text.ParserCombinators.Parsec.Token as P
import Text.ParserCombinators.Parsec.Language( javaStyle )


lexer = P.makeTokenParser techlDef

techlDef = javaStyle
    {
        P.commentLine       = "#",
        P.reservedNames     = [
          "ipv6", "ipv4", "eth", "src", "dst", "type" , "ack", "ackno",
          "urg", "urgno", "syn", "ecne", "cwr", "psh", "rst", "fin"
        ],
        P.reservedOpNames   = ["=", "+", "-", ":", ">>", "<<", "&", "|"],
        P.opLetter          = oneOf (concat (P.reservedOpNames techlDef)),
        P.caseSensitive     = False,
        P.identLetter       = alphaNum <|> oneOf "_'."
    }

parens          :: Parser a -> Parser a
parens          = P.parens lexer
braces          :: Parser a -> Parser a
braces          = P.braces lexer
semiSep         :: Parser a -> Parser [a]
semiSep         = P.semiSep lexer
semiSep1        :: Parser a -> Parser [a]
semiSep1        = P.semiSep1 lexer
commaSep        :: Parser a -> Parser [a]
commaSep        = P.commaSep lexer
commaSep1       :: Parser a -> Parser [a]
commaSep1       = P.commaSep1 lexer
brackets        :: Parser a -> Parser a
brackets        = P.brackets lexer
whiteSpace      :: Parser ()
whiteSpace      = P.whiteSpace lexer
symbol          :: String -> Parser String
symbol          = P.symbol lexer
identifier      :: Parser String
identifier      = P.identifier lexer
reserved        :: String -> Parser ()
reserved        = P.reserved lexer
reservedOp      :: String -> Parser ()
reservedOp      = P.reservedOp lexer
integer         :: Parser Integer
integer         = P.integer lexer
hexadecimal     :: Parser Integer
hexadecimal     = P.hexadecimal lexer
float           :: Parser Double
float           = P.float lexer
charLiteral     :: Parser Char
charLiteral     = P.charLiteral lexer
stringLiteral   :: Parser String
stringLiteral   = P.stringLiteral lexer
naturalOrFloat  :: Parser (Either Integer Double)
naturalOrFloat  = P.naturalOrFloat lexer


