// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract TestNFT is ERC721, Ownable {
    uint256 private _tokenIdCounter;
    string private _baseTokenURI;

    // 🧩 Pass msg.sender to Ownable constructor explicitly (required in OZ v5)
    constructor(string memory baseURI) ERC721("TestNFT", "TNFT") Ownable(msg.sender) {
        _baseTokenURI = baseURI;
    }

    /// @notice Mint new NFT to `to` address
    function mintNFT(address to) external onlyOwner {
        _tokenIdCounter++;
        _safeMint(to, _tokenIdCounter);
    }

    /// @notice Batch mint NFTs
    function mintBatch(address to, uint256 amount) external onlyOwner {
        for (uint256 i = 0; i < amount; i++) {
            _tokenIdCounter++;
            _safeMint(to, _tokenIdCounter);
        }
    }

    /// @notice View total supply minted so far
    function totalMinted() external view returns (uint256) {
        return _tokenIdCounter;
    }

    /// @notice Set new base token URI (optional)
    function setBaseURI(string memory newURI) external onlyOwner {
        _baseTokenURI = newURI;
    }

    /// @dev Override baseURI for metadata
    function _baseURI() internal view override returns (string memory) {
        return _baseTokenURI;
    }
}
