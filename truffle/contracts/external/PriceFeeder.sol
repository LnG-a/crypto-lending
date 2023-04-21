// SPDX-License-Identifier: MIT
pragma solidity >= 0.5.0 < 0.9.0;

import "./provableAPI.sol";

/**
*This contract gets the price from Given URL , and transform the price and sends its back to asking method
*Now we are using this contract when a collateral is claimed or sold, so its sold at the current price retrieved from
* market.
*/


contract PriceFeeder is usingProvable {

  uint256 public price;

  event LogNewProvableQuery(string description);
  event LogNewPrice(uint256 price);


  constructor()
      public
  {


  }

  function __callback(
      bytes32 _myid,
      uint256 _result,
      bytes memory _proof
  )
      public
  {
      require(msg.sender == provable_cbAddress());
      //update(); // Recursively update the price stored in the contract...
      price = _result;

      emit LogNewPrice(price);
  }

  function update(string memory _contractAddress)
      public
      payable
  {
      if (provable_getPrice("URL") > address(this).balance) {
          emit LogNewProvableQuery("Provable query was NOT sent, please add some ETH to cover for the query fee!");
      } else {
          emit LogNewProvableQuery("Provable query was sent, standing by for the answer...");
          string memory url = strConcat("json(https://api.coingecko.com/api/v3/coins/ethereum/contract/", _contractAddress, ").market_data.current_price.usd");
          provable_query("URL",url);
      }
  }
}
