// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "./LoanContract.sol";

contract LoanCreator is Ownable, Pausable {

  address[] public loans;


 constructor() public {

 }

 event LoanOfferCreated(address, address);
 event LoanRequestCreated(address, address);

 // parameters and attributes will change depending on changes in loancontract
 function createNewLoanOffer(uint256 _loanAmount, uint128 _duration, string memory _acceptedCollateralsMetadata) public returns(address _loanContractAddress) {

         _loanContractAddress = address (new LoanContract(_loanAmount, _duration, _acceptedCollateralsMetadata, 0, address(0), 0, 0, 0, address(0), msg.sender, LoanContract.LoanStatus.OFFER));

         loans.push(_loanContractAddress);

         emit LoanOfferCreated(msg.sender, _loanContractAddress);

         return _loanContractAddress;
 }

 function createNewLoanRequest(uint256 _loanAmount, uint128 _duration, uint256 _interest, address _collateralAddress, uint256 _collateralAmount, uint256 _collateralPriceInETH)
 public returns(address _loanContractAddress) {

         _loanContractAddress = address (new LoanContract(_loanAmount, _duration, "", _interest, _collateralAddress, _collateralAmount, _collateralPriceInETH, 50, msg.sender, address(0), LoanContract.LoanStatus.REQUEST));

         loans.push(_loanContractAddress);

         emit LoanRequestCreated(msg.sender, _loanContractAddress);

         return _loanContractAddress;
 }

 function getAllLoans() public view returns(address[] memory){
     return loans;
 }

}
