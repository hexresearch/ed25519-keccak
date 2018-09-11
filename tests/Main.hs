
import           Test.Tasty

import qualified KAT_Ed25519

main :: IO ()
main = defaultMain $ testGroup "test suite"
   [ KAT_Ed25519.tests ]
