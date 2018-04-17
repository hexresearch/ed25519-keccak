{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.Hash.Algorithms
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Definitions of known hash algorithms
--
module Crypto.Hash.Algorithms
    ( HashAlgorithm
    -- * Hash algorithms
    , Keccak_224(..)
    , Keccak_256(..)
    , Keccak_384(..)
    , Keccak_512(..)
    , SHA3_224(..)
    , SHA3_256(..)
    , SHA3_384(..)
    , SHA3_512(..)
    ) where

import           Crypto.Hash.Types (HashAlgorithm)
import           Crypto.Hash.SHA3
import           Crypto.Hash.Keccak
